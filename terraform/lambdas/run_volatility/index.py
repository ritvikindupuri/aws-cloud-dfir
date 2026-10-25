import json
import os
import boto3

ecs = boto3.client('ecs')
EVIDENCE_BUCKET = os.environ.get('EVIDENCE_BUCKET')
ECS_CLUSTER = os.environ.get('ECS_CLUSTER')
TASK_DEFINITION = os.environ.get('TASK_DEFINITION')
SUBNET_ID = os.environ.get('SUBNET_ID')
SECURITY_GROUP_ID = os.environ.get('SECURITY_GROUP_ID')

def handler(event, context):
    """
    Step 5: Launches the Automated Volatility 3 & DFIR Analyzer on ECS Fargate (or records analysis stage).
    """
    print("Launching Volatility analyzer with payload:", json.dumps(event))
    incident_id = event['incident_id']

    task_arn = None
    if ECS_CLUSTER and TASK_DEFINITION:
        try:
            response = ecs.run_task(
                cluster=ECS_CLUSTER,
                taskDefinition=TASK_DEFINITION,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': [SUBNET_ID],
                        'securityGroups': [SECURITY_GROUP_ID],
                        'assignPublicIp': 'ENABLED'
                    }
                },
                overrides={
                    'containerOverrides': [
                        {
                            'name': 'dfir-analyzer',
                            'command': [
                                '--bucket', EVIDENCE_BUCKET,
                                '--incident-id', incident_id
                            ]
                        }
                    ]
                }
            )
            task_arn = response['tasks'][0]['taskArn']
            print(f"Triggered ECS Fargate analysis task: {task_arn}")
        except Exception as e:
            print(f"ECS launch note/error: {e}")

    return {
        "statusCode": 200,
        "incident_id": incident_id,
        "status": "ANALYSIS_SCHEDULED",
        "ecs_task_arn": task_arn,
        "evidence_bucket": EVIDENCE_BUCKET,
        "report_s3_prefix": f"s3://{EVIDENCE_BUCKET}/evidence/{incident_id}/reports/"
    }
