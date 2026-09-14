# Sample: IDR to AWS DevOps Agent Bridge

Sample code that connects AWS DevOps Agent investigation events to AWS Incident
Detection and Response (IDR). One AWS CloudFormation stack deploys both directions of
the integration:

1. **Webhook Proxy** (alarm to DevOps Agent): routes IDR-onboarded alarms to AWS
   DevOps Agent for autonomous investigation via `CreateBacklogTask`.
2. **Bridge Lambda** (DevOps Agent to IDR): catches DevOps Agent investigation
   lifecycle events and republishes them in IDR's `GenericAPMEvent` format so the
   findings appear on the IDR support case.

> **This is sample code, for non-production usage.** You should work with your
> security and legal teams to meet your organizational security, regulatory and
> compliance requirements before deployment.

> **Important — engage your AWS Technical Account Manager (TAM) before you deploy.**
> The direction that posts DevOps Agent findings back to your IDR support case is not
> automatically active. You must tell IDR which alarms you want DevOps Agent findings
> for, so that IDR enables its side of the integration and accepts the findings onto
> the case. Contact your TAM and let them know you intend to deploy this bridge and for
> which set of IDR-onboarded alarms — they will arrange for IDR to enable the DevOps
> Agent feedback for those alarms. Without this step the bridge will publish events but
> the findings will not appear on your IDR case.

## Architecture

```
IDR alarm fires -> EventBridge (default bus)
                     |- Rule: existing IDR flow (opens case)                  <- no change
                     |- Rule: Webhook Proxy -> DevOps Agent CreateBacklogTask <- component 1
                     |- Rule: matches all aws.aidevops investigation events   <- component 2
                                    |
                                    v
                          Bridge Lambda
                                    |
                                    |- fetches the investigation summary
                                    |- publishes a GenericAPMEvent carrying
                                    |  incident-detection-response-identifier: <alarm>
                                    |
                                    v
                          IDR backend correlates on the identifier -> posts to the case
```

## Prerequisites

- An AWS DevOps Agent Space configured in the account and Region you deploy to.
- The account onboarded to AWS Incident Detection and Response, with alarms routed
  through EventBridge (native CloudWatch alarms and/or a third-party APM event bus
  created by the IDR CLI `setup-apm` command).
- **IDR enabled to accept DevOps Agent feedback for your alarms.** Work with your AWS
  TAM to let IDR know which IDR-onboarded alarms should receive DevOps Agent findings,
  so IDR enables the feedback path for those alarms (see the Important note above).
- A boto3 version that includes the `devops-agent` client (ships in the current AWS
  Lambda Python runtime; see `requirements.txt`).

## Files

| File | Purpose |
|------|---------|
| `webhook_proxy.py` | Lambda: alarm to DevOps Agent `CreateBacklogTask` |
| `lambda_function.py` | Lambda: DevOps Agent investigation events to IDR `GenericAPMEvent` |
| `template.yaml` | CloudFormation template (both Lambdas + all EventBridge rules) |
| `tests/` | Sample EventBridge events (for reference / manual testing) |

## Deploy

### Quick deploy with prefix matching (most common)

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name idr-devops-bridge \
  --parameter-overrides \
    AgentSpaceId=<your-agent-space-id> \
    AgentSpaceRegion=us-east-1 \
    AlarmPrefix="IDR-" \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

### Deploy with specific alarm names

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name idr-devops-bridge \
  --parameter-overrides \
    AgentSpaceId=<your-agent-space-id> \
    AgentSpaceRegion=us-east-1 \
    AlarmNames="alarm-1,alarm-2,alarm-3" \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

### Deploy with third-party APM (alongside CloudWatch)

```bash
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name idr-devops-bridge \
  --parameter-overrides \
    AgentSpaceId=<your-agent-space-id> \
    AgentSpaceRegion=us-east-1 \
    AlarmPrefix="IDR-" \
    APMEventBusName="Datadog-AWSIncidentDetectionResponse-EventBus" \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `AgentSpaceId` | Yes | Your DevOps Agent Space ID |
| `AgentSpaceRegion` | Yes | Region where the Agent Space resides |
| `AlarmPrefix` | One of these | Prefix to match alarm names (e.g. `IDR-`) |
| `AlarmNames` | One of these | Comma-separated exact alarm names |
| `APMEventBusName` | No | Custom EventBridge bus from the IDR CLI `setup-apm` |
| `LogLevel` | No | Bridge Lambda log level (default: INFO) |

## Test

```bash
# Force an alarm into ALARM state
aws cloudwatch set-alarm-state \
  --alarm-name "IDR-CLI-Demo-RDS-HighCPU" \
  --state-value ALARM \
  --state-reason "End-to-end test" \
  --region us-east-1

# Watch the webhook proxy logs
aws logs tail /aws/lambda/idr-devops-bridge-webhook-proxy --since 5m --region us-east-1

# Watch the bridge Lambda logs
aws logs tail /aws/lambda/idr-devops-bridge-idr-bridge --since 5m --region us-east-1
```

## Example timings

In a test account, a full alarm to investigation to findings-on-the-IDR-case round
trip completed in about three minutes:

```
00:00  Alarm set to ALARM
00:00  Webhook Proxy -> CreateBacklogTask (priority HIGH)
00:01  Investigation Created    -> Bridge Lambda -> published to IDR
00:08  Investigation In Progress -> Bridge Lambda -> published to IDR
03:06  Investigation Completed   -> Bridge Lambda -> findings published to IDR
```

## Cleanup

```bash
aws cloudformation delete-stack --stack-name idr-devops-bridge --region us-east-1
```

## Notes

- The bridge retrieves the investigation summary with `list_journal_records` (record
  type `investigation_summary_md`) and falls back to the task description if no summary
  record is available. This requires a boto3 version that includes the `devops-agent`
  client — see `requirements.txt`.
- The bridge Lambda is larger than the CloudFormation inline-code limit, so for
  production use deploy it from a package (`aws cloudformation package`) rather than the
  condensed inline copy in `template.yaml`. See `lambda_function.py` for the full
  implementation.

## Related

- [re:Post — Automating AWS DevOps Agent investigation from Incident Detection and Response alarms](https://repost.aws/articles/ARnrvREIynRsKAdzRwYVF1_A/automating-aws-devops-agent-investigation-from-incident-detection-and-response-alarms)
- [AWS DevOps Agent EventBridge events reference](https://docs.aws.amazon.com/devopsagent/latest/userguide/integrating-devops-agent-into-event-driven-applications-using-amazon-eventbridge-devops-agent-events-detail-reference.html)

## Security

See [CONTRIBUTING.md](CONTRIBUTING.md#security-issue-notifications) for how to report security issues.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
