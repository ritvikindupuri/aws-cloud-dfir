import json
import os
import boto3
import uuid
from datetime import datetime, timezone

ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')
s3 = boto3.client('s3')

EVIDENCE_BUCKET = os.environ.get('EVIDENCE_BUCKET')
KMS_KEY_ID = os.environ.get('KMS_KEY_ID')
SSM_DOCUMENT_NAME = os.environ.get('SSM_DOCUMENT_NAME')

def handler(event, context):
    """
    Step 1: Ingests alert (GuardDuty or manual), generates Chain of Custody ID,
    records target instance topology, and triggers live volatile capture via SSM.
    """
    print("Received event:", json.dumps(event))
    
    # 1. Parse target instance ID and alert details
    instance_id = None
    finding_type = "Manual-DFIR-Trigger"
    severity = "HIGH"
    
    # Check if event comes from GuardDuty EventBridge rule
    if "detail" in event and "resource" in event["detail"]:
        detail = event["detail"]
        finding_type = detail.get("type", "Unknown-GuardDuty-Finding")
        severity = str(detail.get("severity", "HIGH"))
        instance_details = detail.get("resource", {}).get("instanceDetails", {})
        instance_id = instance_details.get("instanceId")
    elif "instance_id" in event:
        instance_id = event["instance_id"]
        finding_type = event.get("reason", "Manual Triage Request")
    
    if not instance_id:
        raise ValueError("Could not extract valid EC2 instance_id from input event.")

    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # 2. Inspect target instance topology & current configuration
    res = ec2.describe_instances(InstanceIds=[instance_id])
    reservation = res['Reservations'][0]
    instance_meta = reservation['Instances'][0]
    
    vpc_id = instance_meta.get('VpcId')
    subnet_id = instance_meta.get('SubnetId')
    current_security_groups = [sg['GroupId'] for sg in instance_meta.get('SecurityGroups', [])]
    attached_volumes = [
        {
            'DeviceName': bdm['DeviceName'],
            'VolumeId': bdm['Ebs']['VolumeId'],
            'DeleteOnTermination': bdm['Ebs'].get('DeleteOnTermination', False)
        }
        for bdm in instance_meta.get('BlockDeviceMappings', [])
        if 'Ebs' in bdm
    ]
    
    # 3. Write initial Chain of Custody Manifest to S3
    custody_manifest = {
        "incident_id": incident_id,
        "initiated_at": timestamp,
        "target_instance_id": instance_id,
        "finding_type": finding_type,
        "severity": severity,
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "original_security_groups": current_security_groups,
        "attached_volumes": attached_volumes,
        "chain_of_custody_custodian": "AWS-Cloud-DFIR-Automated-Pipeline",
        "rfc_3227_step": "Step-1-Live-Volatile-Ingest"
    }
    
    s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=f"evidence/{incident_id}/manifest.json",
        Body=json.dumps(custody_manifest, indent=2),
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=KMS_KEY_ID
    )

    # 4. Trigger SSM Live Volatile Collection Document
    ssm_response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName=SSM_DOCUMENT_NAME,
        Parameters={
            'EvidenceBucket': [EVIDENCE_BUCKET],
            'IncidentId': [incident_id],
            'KmsKeyId': [KMS_KEY_ID]
        },
        Comment=f"Cloud DFIR Live Volatile Capture for {incident_id}",
        TimeoutSeconds=1500
    )
    command_id = ssm_response['Command']['CommandId']

    return {
        "statusCode": 200,
        "incident_id": incident_id,
        "instance_id": instance_id,
        "command_id": command_id,
        "original_security_groups": current_security_groups,
        "attached_volumes": attached_volumes,
        "evidence_bucket": EVIDENCE_BUCKET
    }
