# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
IDR Alarm to DevOps Agent Webhook Proxy

Routes IDR alarms (CloudWatch and third-party APM) to AWS DevOps Agent
for autonomous incident investigation via the CreateBacklogTask API.

This runs in PARALLEL with IDR's existing response — it does NOT modify the
IDR alarm flow. It adds a second consumer to the same EventBridge events.

Flow:
1. CloudWatch alarm transitions to ALARM state (or APM sends event to custom bus)
2. EventBridge rule matches the alarm pattern and invokes this Lambda
3. Lambda calls CreateBacklogTask on the DevOps Agent API
4. DevOps Agent begins autonomous investigation

Environment Variables:
    AGENT_SPACE_ID: DevOps Agent Space ID
    AGENT_SPACE_REGION: Region where the Agent Space resides
"""
import json
import os

import boto3

client = boto3.client(
    'devops-agent',
    region_name=os.environ['AGENT_SPACE_REGION']
)


def lambda_handler(event, context):
    """Create a DevOps Agent investigation task from an alarm event."""
    source = event.get("source", "")
    detail = event.get("detail", {})

    if source == "GenericAPMEvent":
        # Third-party APM (Datadog, Dynatrace, Splunk, New Relic)
        incident_id = detail.get(
            "incident-detection-response-identifier",
            event.get("id")
        )
        title = f"APM Alert - {incident_id}"
        description = detail.get(
            "description", "Generic APM event received"
        )
    else:
        # CloudWatch native alarm
        incident_id = detail.get("alarmName", event.get("id"))
        title = f"CloudWatch Alarm: {incident_id}"
        description = detail.get("state", {}).get(
            "reason", "Alarm state changed"
        )

    # Log named identifiers only — never the full inbound event.
    print(json.dumps({
        "message": "Received IDR event",
        "source": source,
        "incidentId": incident_id,
        "region": event.get("region"),
    }))

    resp = client.create_backlog_task(
        agentSpaceId=os.environ['AGENT_SPACE_ID'],
        taskType='INVESTIGATION',
        priority='HIGH',
        title=title,
        description=json.dumps({
            "summary": description,
            "incidentId": incident_id,
            "incidentRegion": event.get("region"),
        })
    )
    print(json.dumps({
        "message": "Created task",
        "taskId": resp.get('taskId', resp.get('backlogTaskId', ''))
    }))

    return {
        'statusCode': 200,
        'body': json.dumps({
            'taskId': resp.get('taskId', resp.get('backlogTaskId', ''))
        })
    }
