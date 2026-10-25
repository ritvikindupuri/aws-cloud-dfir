import json
import os
import boto3

ec2 = boto3.client('ec2')
QUARANTINE_SG_ID = os.environ.get('QUARANTINE_SG_ID')

def handler(event, context):
    """
    Step 2: Enforces immediate Zero-Trust Network Quarantine.
    Replaces existing security groups with the Quarantine SG and sets tamper-protection tags.
    """
    print("Isolating instance payload:", json.dumps(event))
    
    instance_id = event['instance_id']
    incident_id = event['incident_id']
    
    # 1. Enable termination protection so the compromised host cannot be deleted
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': True}
        )
    except Exception as e:
        print(f"Warning: Could not set DisableApiTermination: {e}")

    # 2. Swap network security groups to Quarantine SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG_ID]
    )

    # 3. Apply forensic quarantine tags to the instance
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {'Key': 'DFIR_Status', 'Value': 'Quarantined'},
            {'Key': 'DFIR_IncidentId', 'Value': incident_id},
            {'Key': 'DFIR_EvidencePreservation', 'Value': 'DO_NOT_DELETE'},
            {'Key': 'DFIR_OriginalSecurityGroups', 'Value': ','.join(event.get('original_security_groups', []))}
        ]
    )

    print(f"Instance {instance_id} successfully quarantined with SG {QUARANTINE_SG_ID}")

    return {
        "statusCode": 200,
        "incident_id": incident_id,
        "instance_id": instance_id,
        "quarantine_sg_id": QUARANTINE_SG_ID,
        "status": "QUARANTINED",
        "attached_volumes": event.get('attached_volumes', [])
    }
