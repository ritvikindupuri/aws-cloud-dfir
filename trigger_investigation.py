#!/usr/bin/env python3
"""
AWS Cloud DFIR: Autonomous Investigation CLI Trigger & Progress Monitor
Triggers the Step Functions State Machine and monitors investigation progress in real-time.
"""

import sys
import json
import time
import argparse
from datetime import datetime, timezone
import boto3

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Autonomous Cloud DFIR Pipeline Trigger")
    parser.add_argument("--instance-id", required=True, help="Target EC2 Instance ID under investigation")
    parser.add_argument("--reason", default="GuardDuty Alert: UnauthorizedAccess:EC2/TorIPCaller", help="Trigger reason")
    parser.add_argument("--state-machine-arn", help="ARN of the DFIR Step Functions State Machine")
    parser.add_argument("--region", default="us-east-1", help="AWS Region")
    parser.add_argument("--wait", action="store_true", help="Wait and tail execution progress")
    args = parser.parse_args()

    sfn = boto3.client('stepfunctions', region_name=args.region)
    s3 = boto3.client('s3', region_name=args.region)

    state_machine_arn = args.state_machine_arn
    if not state_machine_arn:
        # Find state machine by name prefix
        machines = sfn.list_state_machines()['stateMachines']
        match = next((m['stateMachineArn'] for m in machines if "cloud-dfir" in m['name'].lower()), None)
        if match:
            state_machine_arn = match
        else:
            print("[-] Could not automatically locate Cloud DFIR Step Functions State Machine.")
            print("    Please provide --state-machine-arn explicitly.")
            sys.exit(1)

    execution_name = f"DFIR-{args.instance_id}-{int(time.time())}"
    payload = {
        "instance_id": args.instance_id,
        "reason": args.reason,
        "triggered_by": "Cloud-DFIR-CLI",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    print("==============================================================================")
    print("[!] INITIATING AUTONOMOUS AWS CLOUD DFIR PIPELINE (RFC 3227 ORDER OF VOLATILITY)")
    print("==============================================================================")
    print(f"Target Instance:      {args.instance_id}")
    print(f"Investigation Reason: {args.reason}")
    print(f"State Machine ARN:    {state_machine_arn}")
    print(f"Execution Name:       {execution_name}")
    print("------------------------------------------------------------------------------")

    response = sfn.start_execution(
        stateMachineArn=state_machine_arn,
        name=execution_name,
        input=json.dumps(payload)
    )
    execution_arn = response['executionArn']
    print(f"[+] Execution launched: {execution_arn}")

    if not args.wait:
        print("[*] Pipeline running asynchronously in AWS Step Functions.")
        return

    print("[*] Streaming workflow stage progress...")
    seen_events = set()
    completed = False
    
    while not completed:
        desc = sfn.describe_execution(executionArn=execution_arn)
        status = desc['status']
        
        hist = sfn.get_execution_history(executionArn=execution_arn, reverseOrder=False)
        for ev in hist['events']:
            ev_id = ev['id']
            if ev_id not in seen_events:
                seen_events.add(ev_id)
                ev_type = ev['type']
                if "StateEntered" in ev_type:
                    state_name = ev.get('stateEnteredEventDetails', {}).get('name', 'Unknown')
                    print(f"  [STAGE ENTERED] : {state_name}")
                elif "ExecutionFailed" in ev_type:
                    print(f"  [ERROR]         : {ev.get('executionFailedEventDetails', {})}")
                elif "ExecutionSucceeded" in ev_type:
                    print(f"  [SUCCESS]       : DFIR Pipeline Completed Successfully!")

        if status in ['SUCCEEDED', 'FAILED', 'TIMED_OUT', 'ABORTED']:
            completed = True
            print("------------------------------------------------------------------------------")
            print(f"Final Pipeline Status: {status}")
            if status == 'SUCCEEDED':
                output = json.loads(desc.get('output', '{}'))
                incident_id = output.get('incident_id')
                report_prefix = output.get('report_s3_prefix')
                print(f"Incident Tracking ID: {incident_id}")
                print(f"Forensic Report S3:   {report_prefix}")
            break
        
        time.sleep(5)

if __name__ == "__main__":
    main()
