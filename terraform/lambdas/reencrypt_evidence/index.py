import json
import os
import boto3
from datetime import datetime, timezone

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')

FORENSICS_KMS_KEY_ARN = os.environ.get('FORENSICS_KMS_KEY_ARN')
EVIDENCE_BUCKET = os.environ.get('EVIDENCE_BUCKET')

def handler(event, context):
    """
    Step 4: Re-encrypts snapshots with dedicated Forensics KMS CMK.
    Updates the S3 Evidence Manifest with final snapshot integrity and storage locations.
    """
    print("Re-encrypt payload:", json.dumps(event))
    
    incident_id = event['incident_id']
    instance_id = event['instance_id']
    snapshots = event.get('snapshots', [])
    reencrypted_snapshots = []
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    
    for snap in snapshots:
        src_snap_id = snap['SnapshotId']
        vol_id = snap['VolumeId']
        device = snap['DeviceName']
        
        # Copy and re-encrypt with dedicated forensics KMS key
        copy_res = ec2.copy_snapshot(
            SourceSnapshotId=src_snap_id,
            SourceRegion=os.environ.get('AWS_REGION', 'us-east-1'),
            Description=f"Encrypted Forensics Vault Copy - {incident_id} - Vol {vol_id}",
            Encrypted=True,
            KmsKeyId=FORENSICS_KMS_KEY_ARN,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f"DFIR-EncryptedVault-{incident_id}-{vol_id}"},
                        {'Key': 'DFIR_IncidentId', 'Value': incident_id},
                        {'Key': 'DFIR_SourceSnapshotId', 'Value': src_snap_id},
                        {'Key': 'DFIR_VaultStatus', 'Value': 'IMMUTABLE_ENCRYPTED'},
                        {'Key': 'DFIR_PreservationTime', 'Value': timestamp}
                    ]
                }
            ]
        )
        
        vault_snap_id = copy_res['SnapshotId']
        print(f"Initiated re-encrypted copy {vault_snap_id} for source snapshot {src_snap_id}")
        
        reencrypted_snapshots.append({
            "OriginalSnapshotId": src_snap_id,
            "VaultSnapshotId": vault_snap_id,
            "VolumeId": vol_id,
            "DeviceName": device,
            "KmsKeyArn": FORENSICS_KMS_KEY_ARN
        })
        
    # Update Evidence Manifest in S3 with snapshot records
    manifest_key = f"evidence/{incident_id}/manifest.json"
    try:
        current_obj = s3.get_object(Bucket=EVIDENCE_BUCKET, Key=manifest_key)
        manifest_data = json.loads(current_obj['Body'].read().decode('utf-8'))
        manifest_data['ebs_forensic_snapshots'] = reencrypted_snapshots
        manifest_data['completed_stages'] = ["LiveVolatile", "NetworkQuarantine", "EBSSnapshots", "KMSEncryption"]
        manifest_data['last_updated'] = timestamp
        
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=manifest_key,
            Body=json.dumps(manifest_data, indent=2),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=FORENSICS_KMS_KEY_ARN
        )
    except Exception as e:
        print(f"Warning updating S3 manifest: {e}")

    return {
        "statusCode": 200,
        "incident_id": incident_id,
        "instance_id": instance_id,
        "reencrypted_snapshots": reencrypted_snapshots,
        "evidence_bucket": EVIDENCE_BUCKET
    }
