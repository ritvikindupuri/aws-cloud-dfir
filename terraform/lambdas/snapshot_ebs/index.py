import json
import boto3
from datetime import datetime, timezone

ec2 = boto3.client('ec2')

def handler(event, context):
    """
    Step 3: Creates point-in-time crash-consistent EBS snapshots for all attached volumes,
    annotating each with chain-of-custody tags.
    """
    print("Snapshot payload:", json.dumps(event))
    
    instance_id = event['instance_id']
    incident_id = event['incident_id']
    attached_volumes = event.get('attached_volumes', [])
    created_snapshots = []
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    
    for vol in attached_volumes:
        vol_id = vol['VolumeId']
        device_name = vol['DeviceName']
        
        description = f"Cloud DFIR Forensic Snapshot - {incident_id} - Vol {vol_id} ({device_name})"
        
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=description,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f"DFIR-Snapshot-{incident_id}-{vol_id}"},
                        {'Key': 'DFIR_IncidentId', 'Value': incident_id},
                        {'Key': 'DFIR_SourceInstanceId', 'Value': instance_id},
                        {'Key': 'DFIR_SourceVolumeId', 'Value': vol_id},
                        {'Key': 'DFIR_DeviceName', 'Value': device_name},
                        {'Key': 'DFIR_PreservationTime', 'Value': timestamp},
                        {'Key': 'DFIR_ChainOfCustody', 'Value': 'Automated-Orchestrator'}
                    ]
                }
            ]
        )
        
        snapshot_id = snap['SnapshotId']
        print(f"Created forensic snapshot {snapshot_id} for volume {vol_id}")
        
        created_snapshots.append({
            "SnapshotId": snapshot_id,
            "VolumeId": vol_id,
            "DeviceName": device_name
        })
        
    return {
        "statusCode": 200,
        "incident_id": incident_id,
        "instance_id": instance_id,
        "snapshots": created_snapshots
    }
