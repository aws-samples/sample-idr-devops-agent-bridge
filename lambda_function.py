# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
IDR Bridge Lambda — Transforms DevOps Agent investigation events into GenericAPM format.

Uses the GenericAPM event model that IDR's existing systems already recognise:
  - source: "GenericAPMEvent"
  - detail-type: "ams.monitoring/generic-apm"
  - detail.incident-detection-response-identifier: <alarm IDR identifier>

This ensures the event is caught by EROS's GenericEvents pattern and routed
through MMS deduplication to the correct SIM ticket — with zero backend changes.

The key field for deduplication is `incident-detection-response-identifier`.
MMS constructs a manufactured ARN from this identifier (event source is NOT
included in the ARN), so events with the same identifier update the same ticket.

Flow:
1. DA publishes "Investigation In Progress" or "Investigation Completed" to default EB
2. This Lambda catches it (rule matches source: aws.aidevops)
3. Lambda transforms into GenericAPM format and publishes to default EB
4. EROS GenericEvents pattern matches (has incident-detection-response-identifier)
5. MMS deduplicates and adds findings as comment to existing SIM ticket

Environment Variables:
    LOG_LEVEL: Logging level (default: INFO)
"""
import json
import logging
import os
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Clients
devops_agent = boto3.client("devops-agent")
events_client = boto3.client("events")

# GenericAPM event constants
GENERIC_APM_SOURCE = "GenericAPMEvent"
GENERIC_APM_DETAIL_TYPE = "ams.monitoring/generic-apm"


def handler(event, context):
    """Transform DevOps Agent events into GenericAPM format for IDR consumption."""
    logger.info(json.dumps({
        "message": "Received DevOps Agent event",
        "detail_type": event.get("detail-type"),
        "task_id": event.get("detail", {}).get("metadata", {}).get("task_id"),
        "execution_id": event.get("detail", {}).get("metadata", {}).get("execution_id"),
    }))

    detail_type = event.get("detail-type", "")
    detail = event.get("detail", {})
    metadata = detail.get("metadata", {})
    data = detail.get("data", {})
    region = event.get("region", os.environ.get("AWS_REGION"))
    account_id = event.get("account", "")

    agent_space_id = metadata.get("agent_space_id")
    task_id = metadata.get("task_id")
    execution_id = metadata.get("execution_id")
    summary_record_id = data.get("summary_record_id")
    priority = data.get("priority", "UNKNOWN")
    created_at = data.get("created_at", "")
    updated_at = data.get("updated_at", "")

    if not agent_space_id or not task_id:
        logger.error("Missing agent_space_id or task_id")
        return {"statusCode": 400, "body": "Missing required metadata"}

    # Get the IDR identifier — this is the alarm name/ID that IDR uses to correlate
    # It comes from the original alarm event that triggered DA
    idr_identifier = get_idr_identifier(agent_space_id, task_id)

    if not idr_identifier:
        logger.warning(f"Could not determine IDR identifier for task {task_id}")
        # Use task_id as fallback — IDR may still be able to correlate
        idr_identifier = task_id

    now = datetime.utcnow()
    now_epoch_ms = int(now.timestamp() * 1000)

    # ─── INVESTIGATION IN PROGRESS ─────────────────────────────────────────
    if detail_type in ("Investigation Created", "Investigation In Progress", "Investigation Priority Updated"):
        title = (f"DevOps Agent investigation triggered (Priority: {priority}). "
                 f"Analysing CloudWatch metrics, logs, traces, and resource configurations. "
                 f"Findings will follow shortly.")
        if detail_type == "Investigation Priority Updated":
            title = f"DevOps Agent: Investigation priority updated to {priority}."

        idr_event = build_generic_apm_event(
            idr_identifier=idr_identifier,
            title=title,
            priority=priority,
            state="CREATED" if detail_type == "Investigation Created" else "ACTIVATED",
            sources=["devops-agent"],
            description=(f"Investigation in progress — root cause not yet determined. "
                         f"Triggered by: IDR alarm trigger → DevOps Agent (task: {task_id})"),
            created_at_ms=now_epoch_ms,
            updated_at_ms=now_epoch_ms,
            investigation_context={
                "phase": "in_progress",
                "investigationCompleted": False,
                "taskId": task_id,
                "executionId": execution_id,
            },
        )
        result = publish_to_eventbridge(idr_event, region)
        return {"statusCode": 200, "body": f"Posted '{detail_type}' for {idr_identifier}", "task_id": task_id, "phase": "in_progress", "event_id": result}

    # ─── INVESTIGATION COMPLETED ───────────────────────────────────────────
    if detail_type == "Investigation Completed":
        summary_text, findings_list = get_investigation_findings(
            agent_space_id, task_id, execution_id, summary_record_id
        )
        root_causes = extract_root_causes(summary_text)
        impact = extract_impact(summary_text)

        # Build a rich description combining summary + findings for the SIM comment
        description = build_description(summary_text, root_causes, impact, findings_list, task_id)

        created_at_ms = now_epoch_ms
        if created_at:
            try:
                created_at_ms = int(datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp() * 1000)
            except (ValueError, TypeError):
                pass

        idr_event = build_generic_apm_event(
            idr_identifier=idr_identifier,
            title=f"DevOps Agent Investigation Complete - {idr_identifier}",
            priority=priority,
            state="ACTIVATED",
            sources=["devops-agent"],
            description=description,
            created_at_ms=created_at_ms,
            updated_at_ms=now_epoch_ms,
            investigation_context={
                "phase": "completed",
                "investigationCompleted": True,
                "summary": summary_text,
                "rootCauses": root_causes,
                "impact": impact,
                "findings": findings_list,
                "taskId": task_id,
                "executionId": execution_id,
            },
        )
        result = publish_to_eventbridge(idr_event, region)
        return {"statusCode": 200, "body": f"Posted findings for {idr_identifier}", "task_id": task_id, "phase": "completed", "event_id": result}

    # ─── INVESTIGATION TERMINAL STATES ─────────────────────────────────────
    if detail_type in ("Investigation Failed", "Investigation Timed Out", "Investigation Cancelled",
                       "Investigation Pending Triage", "Investigation Linked", "Investigation Skipped"):
        status = data.get("status", detail_type.replace("Investigation ", "").upper())
        title = f"DevOps Agent investigation {status.lower()}."
        if detail_type == "Investigation Pending Triage":
            title = "DevOps Agent: Investigation pending triage — awaiting prioritisation."
        elif detail_type == "Investigation Linked":
            title = "DevOps Agent: Investigation linked to existing investigation."
        elif detail_type == "Investigation Skipped":
            title = "DevOps Agent: Investigation skipped — duplicate or low priority."

        idr_event = build_generic_apm_event(
            idr_identifier=idr_identifier,
            title=title,
            priority=priority,
            state="CLOSED" if "Cancelled" in detail_type or "Skipped" in detail_type else "ACTIVATED",
            sources=["devops-agent"],
            description=f"Investigation {status.lower()}. Task: {task_id}",
            created_at_ms=now_epoch_ms,
            updated_at_ms=now_epoch_ms,
            investigation_context={
                "phase": status.lower(),
                "investigationCompleted": False,
                "taskId": task_id,
                "executionId": execution_id,
            },
        )
        result = publish_to_eventbridge(idr_event, region)
        return {"statusCode": 200, "body": f"Posted '{detail_type}' for {idr_identifier}", "task_id": task_id, "phase": status.lower(), "event_id": result}

    logger.info(f"Unhandled detail-type: {detail_type}")
    return {"statusCode": 200, "body": f"Skipped: {detail_type}"}


def build_generic_apm_event(
    idr_identifier: str,
    title: str,
    priority: str,
    state: str,
    sources: list,
    description: str,
    created_at_ms: int,
    updated_at_ms: int,
    investigation_context: dict,
) -> dict:
    """Build event in GenericAPM format that IDR's existing systems recognise.

    The GenericAPM schema requires these top-level detail fields:
    - title: Human-readable title
    - priority: CRITICAL, HIGH, MEDIUM, LOW
    - state: ACTIVATED, CREATED, CLOSED
    - sources: list of source identifiers
    - createdAt: epoch ms
    - updatedAt: epoch ms
    - incident-detection-response-identifier: THE key field for MMS deduplication

    Additional fields are passed through as-is by MMS when adding as SIM comment.
    """
    return {
        "source": GENERIC_APM_SOURCE,
        "detail-type": GENERIC_APM_DETAIL_TYPE,
        "detail": {
            "title": title,
            "priority": priority,
            "state": state,
            "sources": sources,
            "createdAt": created_at_ms,
            "updatedAt": updated_at_ms,
            "incident-detection-response-identifier": idr_identifier,
            "description": description,
            # Investigation context as additional structured data
            # MMS passes all fields through when adding as SIM comment
            "investigationContext": investigation_context,
        }
    }


def build_description(summary_text: str, root_causes: str, impact: str, findings: list, task_id: str) -> str:
    """Build a formatted description combining all investigation outputs."""
    parts = []
    parts.append(f"## DevOps Agent Investigation Summary (task: {task_id})")
    parts.append("")

    if impact and impact != "See investigation summary":
        parts.append(f"**Impact:** {impact}")
        parts.append("")

    if root_causes and root_causes != "See investigation summary":
        parts.append(f"**Root Causes:** {root_causes}")
        parts.append("")

    if findings:
        parts.append("**Key Findings:**")
        for f in findings[:10]:
            parts.append(f"- {f}")
        parts.append("")

    if summary_text:
        parts.append("**Full Summary:**")
        # Truncate to avoid hitting EB 256KB limit per entry detail
        if len(summary_text) > 50000:
            parts.append(summary_text[:50000] + "\n... [truncated]")
        else:
            parts.append(summary_text)

    return "\n".join(parts)


def publish_to_eventbridge(idr_event: dict, region: str) -> str:
    """Publish the transformed event to EventBridge default bus."""
    detail_json = json.dumps(idr_event["detail"])

    # Check size limit (256KB per entry)
    event_size = len(detail_json.encode("utf-8"))
    if event_size > 262144:
        logger.warning(f"Event detail size {event_size} exceeds 256KB, truncating description")
        # Truncate the description field to fit
        idr_event["detail"]["description"] = idr_event["detail"]["description"][:10000] + "\n... [truncated — event too large]"
        idr_event["detail"]["investigationContext"]["summary"] = ""
        idr_event["detail"]["investigationContext"]["findings"] = []
        detail_json = json.dumps(idr_event["detail"])

    logger.info(f"Publishing to EventBridge: source={idr_event['source']}, "
                f"detail-type={idr_event['detail-type']}, "
                f"idr_id={idr_event['detail']['incident-detection-response-identifier']}, "
                f"size={event_size}")

    response = events_client.put_events(
        Entries=[{
            "Detail": detail_json,
            "DetailType": idr_event["detail-type"],
            "Source": idr_event["source"],
            "EventBusName": "default"
        }]
    )

    event_id = response["Entries"][0].get("EventId", "unknown")
    failed = response.get("FailedEntryCount", 0)
    if failed > 0:
        error = response["Entries"][0]
        logger.error(f"Failed to publish event: {error.get('ErrorCode')} - {error.get('ErrorMessage')}")
    else:
        logger.info(f"Published event: {event_id}")
    return event_id


def get_idr_identifier(agent_space_id: str, task_id: str) -> str:
    """Get the IDR identifier (alarm name) from the task that triggered this investigation.

    The task title typically contains the alarm name since DA was triggered by that alarm.
    Format from webhook proxy: "CloudWatch Alarm: <alarm-name>" or "APM Alert - <id>".
    We strip the prefix to get the raw identifier that matches what IDR uses.
    """
    try:
        response = devops_agent.get_backlog_task(
            agentSpaceId=agent_space_id,
            taskId=task_id
        )
        task = response.get("task", {})
        title = task.get("title", "")

        if not title:
            return task_id

        # Strip webhook proxy prefixes to get raw alarm/APM identifier
        if title.startswith("CloudWatch Alarm: "):
            return title[len("CloudWatch Alarm: "):]
        if title.startswith("APM Alert - "):
            return title[len("APM Alert - "):]

        return title
    except Exception as e:
        logger.warning(f"Could not fetch task title for IDR identifier: {e}")
        return None


def get_investigation_findings(agent_space_id: str, task_id: str, execution_id: str = None, summary_record_id: str = None):
    """Retrieve investigation summary and findings from DevOps Agent.

    Tries multiple methods in order of preference:
    1. Journal record by summary_record_id (direct)
    2. list_journal_records with investigation_summary_md type (markdown)
    3. list_journal_records with investigation_summary type (JSON)
    4. Task description (fallback)

    Returns (summary_text, findings_list)
    """
    summary_text = ""
    findings_list = []

    try:
        # Method 1: Direct journal record by ID
        if summary_record_id:
            try:
                response = devops_agent.get_journal_record(
                    agentSpaceId=agent_space_id,
                    taskId=task_id,
                    recordId=summary_record_id
                )
                content = response.get("content", "")
                if content:
                    summary_text = content
                    findings_list = extract_findings_list(content)
                    return summary_text, findings_list
            except Exception as e:
                logger.warning(f"Could not fetch journal record {summary_record_id}: {e}")

        # Method 2: List journal records — markdown summary
        if execution_id:
            try:
                journal_resp = devops_agent.list_journal_records(
                    agentSpaceId=agent_space_id,
                    executionId=execution_id,
                    recordType='investigation_summary_md'
                )
                for record in journal_resp.get('records', []):
                    if record.get('recordType') == 'investigation_summary_md':
                        content = record.get('content', '')
                        if content:
                            summary_text = content
                            findings_list = extract_findings_list(content)
                            logger.info(f"Retrieved investigation_summary_md ({len(content)} chars)")
                            return summary_text, findings_list
            except Exception as e:
                logger.warning(f"list_journal_records (md) failed: {e}")

        # Method 3: List journal records — structured JSON summary
        if execution_id:
            try:
                journal_resp = devops_agent.list_journal_records(
                    agentSpaceId=agent_space_id,
                    executionId=execution_id,
                    recordType='investigation_summary'
                )
                for record in journal_resp.get('records', []):
                    if record.get('recordType') == 'investigation_summary':
                        parsed = json.loads(record.get('content', '{}'))
                        summary_text = json.dumps(parsed, indent=2)
                        if parsed.get('findings'):
                            findings_list = [f.get('description', '') for f in parsed['findings'] if f.get('description')]
                        return summary_text, findings_list
            except Exception as e:
                logger.warning(f"list_journal_records (json) failed: {e}")

        # Method 4: Fallback to task description
        response = devops_agent.get_backlog_task(
            agentSpaceId=agent_space_id,
            taskId=task_id
        )
        task = response.get("task", {})
        summary_text = task.get("description", "Investigation completed — details in DevOps Agent console")
        return summary_text, findings_list

    except Exception as e:
        logger.error(f"Failed to retrieve findings: {e}")
        return "Investigation completed — unable to retrieve detailed findings", []


def extract_root_causes(summary_text: str) -> str:
    """Extract root cause section from investigation summary markdown."""
    lines = summary_text.split("\n")
    capturing = False
    root_cause_lines = []

    for line in lines:
        lower = line.lower()
        if "root cause" in lower or "cause:" in lower:
            capturing = True
            root_cause_lines.append(line)
        elif capturing and (line.startswith("#") or line.startswith("**Impact") or line.startswith("**Recommendation")):
            break
        elif capturing:
            root_cause_lines.append(line)

    return "\n".join(root_cause_lines).strip() if root_cause_lines else "See investigation summary"


def extract_impact(summary_text: str) -> str:
    """Extract impact section from investigation summary markdown."""
    lines = summary_text.split("\n")
    capturing = False
    impact_lines = []

    for line in lines:
        lower = line.lower()
        if "impact" in lower and ("**" in line or "#" in line):
            capturing = True
            impact_lines.append(line)
        elif capturing and (line.startswith("#") or line.startswith("**Evidence") or line.startswith("**Recommendation")):
            break
        elif capturing:
            impact_lines.append(line)

    return "\n".join(impact_lines).strip() if impact_lines else "See investigation summary"


def extract_findings_list(summary_text: str) -> list:
    """Extract individual findings as a list from the summary markdown."""
    findings = []
    lines = summary_text.split("\n")

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- ") or stripped.startswith("* "):
            findings.append(stripped[2:])

    return findings[:20]  # Cap at 20 findings to avoid event size issues
