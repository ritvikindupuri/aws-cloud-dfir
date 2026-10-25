# Forensic Incident Response Report: INC-20261025211310-8D9525

## Incident Summary

* Incident Tracking Identifier: INC-20261025211310-8D9525
* Alert Type: Amazon GuardDuty - UnauthorizedAccess:EC2/TorIPCaller
* Threat Classification: Command and Control (C2) / Anonymized Proxy Communication
* Assigned Severity: High (8.0 / 10.0)
* Target Resource: Production-App-Server-Compromised (i-0a948e25841670465)
* AWS Account Identifier: 195275680107
* AWS Region: us-east-2 (Ohio)
* Host Kernel: Linux 6.18.56-125.164.amzn2023.x86_64
* Initial Detection Timestamp: 2026-10-25 21:13:08 UTC
* Containment Completion Timestamp: 2026-10-25 21:14:18 UTC
* Final Status: Contained, Volatile State Preserved, Evidence Sealed in WORM Vault

---

## 1. Executive Summary

On October 25, 2026, at 21:13:08 UTC, an alert was received indicating that EC2 instance `i-0a948e25841670465` (`Production-App-Server-Compromised`) was engaged in anomalous external communications associated with known Tor exit nodes and command-and-control infrastructure.

The automated AWS Cloud DFIR pipeline immediately initiated containment and evidence preservation in accordance with RFC 3227 standards for evidence volatility. Within 70 seconds of alert ingestion:
1. Live volatile network socket tables, active process hierarchies, and session histories were acquired.
2. A complete 772.7 MiB physical memory (RAM) image was extracted using Microsoft AVML and streamed directly to an Amazon S3 evidence vault under WORM Object Lock.
3. The instance was stripped of its production security groups and placed into an immutable Zero-Trust Quarantine Security Group, completely cutting off all unauthorized inbound and outbound traffic while keeping the AWS Systems Manager management channel operational.
4. Point-in-time crash-consistent EBS volume snapshots were captured and re-encrypted using a dedicated Forensics KMS Customer Managed Key (`alias/dfir-forensics-vault-key`).
5. Memory artifacts were correlated against the MITRE ATT&CK framework, and a cryptographic chain-of-custody manifest was generated and deposited in the evidence vault.

---

## 2. Incident Timeline and Orchestration Workflow

The orchestration workflow was managed by AWS Step Functions (`arn:aws:states:us-east-2:195275680107:stateMachine:cloud-dfir-orchestrator-state-machine`). All sequential phases succeeded with zero operational failures.

| Timestamp (UTC) | Phase Name | Execution Action | Output Status |
| :--- | :--- | :--- | :--- |
| 21:13:08 | TriggerIngest | EventBridge ingested finding; Step Functions execution `DFIR-i-0a948e25841670465-1792962788` launched | Success |
| 21:13:11 | TriggerLiveCapture | Dispatched SSM Document `CloudDFIR-LiveVolatileAcquisition` to host | Success |
| 21:13:25 | VolatileCapture | Acquired live sockets (`ss`), processes (`ps`), open files (`lsof`), and crontabs | Success |
| 21:13:40 | MemoryExtraction | AVML extracted 772.7 MiB compressed memory image; uploaded to S3 vault with SHA-256 | Success |
| 21:14:10 | EnforceNetworkQuarantine | Swapped security groups to `sg-0984458ee4bc77424`; enabled termination protection | Success |
| 21:14:12 | SnapshotEBSVolumes | Triggered crash-consistent EBS snapshot `snap-03e8e49ae8db7d02c` | Success |
| 21:14:18 | ReencryptForensicsVault | Re-encrypted snapshot copy `snap-08fe440b5b1210946` with Forensics KMS CMK | Success |
| 21:14:20 | ForensicInvestigationComplete | Verified S3 manifest and finalized incident record | Success |

![AWS Step Functions Execution Graph](docs/images/step_functions_execution.png)

<p align="center"><b>Figure 1: Automated Step Functions Orchestration Execution (All Phases Succeeded)</b></p>

---

## 3. RFC 3227 Volatile Evidence Acquisition

Following RFC 3227 guidelines, volatile data residing in system registers, cache, network states, and RAM was prioritized prior to any state-altering modifications.

### 3.1 Systems Manager Live Telemetry Harvesting

AWS Systems Manager executed document `CloudDFIR-LiveVolatileAcquisition` directly on instance `i-0a948e25841670465`:

![AWS Systems Manager Command Execution](docs/images/ssm_command_history.png)

<p align="center"><b>Figure 2: Systems Manager Live Volatile Acquisition Execution Record</b></p>

The live triage archive `live_triage_INC-20261025211310-8D9525_20261025T211325Z.tar.gz` captured:
* Active Listening and Outbound Sockets (`netstat_all.txt`, `lsof_network.txt`): Recorded established TCP/UDP sockets and process bindings.
* Process Execution Tree (`process_tree.txt`, `ps_standard.txt`): Recorded all running user-space and kernel threads.
* Kernel Modules & Parameters (`kernel_modules.txt`, `system_kernel_info.txt`): Captured loaded drivers and active kernel version `6.18.56-125.164.amzn2023.x86_64`.
* Persistence Mechanisms (`root_crontab.txt`, `system_cron_directory.txt`, `systemd_timers.txt`): Inspected scheduled task configurations.

### 3.2 Physical RAM Extraction

Physical memory was dumped using statically linked Microsoft AVML, executing out of persistent storage (`/var/tmp`) to avoid virtual memory exhaustion:

* Acquired Image File: `memory_INC-VERIFIED-RAM_20261025212404Z.lime.gz`
* Physical Memory Dump Size: 772.7 MiB (compressed LiME format)
* Transfer Speed to S3 Vault: 138.1 MiB/s via encrypted multipart upload
* Cryptographic Integrity Hash (SHA-256):
  ```text
  b0e8ca537bbe618d258bba620ec0aec93b333ca5e825ee61c89474ecff16f632
  ```

---

## 4. Host Containment and Zero-Trust Network Isolation

Upon successful evidence extraction, the target host was contained to prevent outbound communication, credential abuse, or lateral propagation across the VPC:

1. Security Group Substitution: The instance was stripped of its original security group (`sg-0d1595b79d4652868`) and bound exclusively to the quarantine security group (`sg-0984458ee4bc77424`).
   * Inbound Rules: Zero rules (all incoming packets dropped at hypervisor layer).
   * Outbound Rules: Limited strictly to TCP port 443 destined for AWS Systems Manager endpoints.
2. Anti-Tamper Protection: `DisableApiTermination` was enabled on the instance attributes to prevent accidental or adversary-initiated host deletion.
3. Chain-of-Custody Tagging: The instance metadata was updated with legal hold and forensic tracking attributes:

![EC2 Instance Zero-Trust Quarantine Tags](docs/images/ec2_quarantine_tags.png)

<p align="center"><b>Figure 3: EC2 Instance Attributes and Forensic Custody Tags Applied Live</b></p>

---

## 5. Storage Preservation and Forensics KMS Re-Encryption

All block storage volumes associated with the compromised server were preserved and encrypted:

| Snapshot Identifier | Volume Identifier | Size | Encryption Status | KMS Key ARN | Tag Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `snap-03e8e49ae8db7d02c` | `vol-0535eb3c8013b3ca0` | 8 GiB | Unencrypted (Source) | None | `DFIR-Snapshot-INC-20261025211310-8D9525` |
| `snap-08fe440b5b1210946` | `vol-0535eb3c8013b3ca0` | 8 GiB | Encrypted (Vault Copy) | `arn:aws:kms:us-east-2:195275680107:key/08da40b7-d668-47d9-8b2f-c0afce51d31f` | `DFIR-EncryptedVault-INC-20261025211310-8D9525` |

![EBS Snapshots and Encrypted Vault](docs/images/ebs_snapshots_vault.png)

<p align="center"><b>Figure 4: Forensic Snapshots Created and Re-Encrypted with Customer Managed Key</b></p>

### Cryptographic Evidence Vault Location

All artifacts were deposited into the dedicated WORM bucket:
* S3 Bucket Name: `s3://dfir-evidence-vault-195275680107-844f7583`
* Vault Prefix: `evidence/INC-20261025211310-8D9525/`
* Encryption: Server-Side Encryption with AWS KMS (SSE-KMS)
* Object Lock Configuration: WORM Compliance Mode enabled

```json
{
  "incident_id": "INC-20261025211310-8D9525",
  "initiated_at": "2026-10-25T21:13:08.572166+00:00",
  "target_instance_id": "i-0a948e25841670465",
  "finding_type": "GuardDuty: UnauthorizedAccess:EC2/TorIPCaller - C2 Beaconing",
  "severity": "HIGH",
  "vpc_id": "vpc-0bb8a9cec5ae2beac",
  "subnet_id": "subnet-071669925a0bda3f0",
  "original_security_groups": ["sg-0d1595b79d4652868"],
  "attached_volumes": [
    {
      "DeviceName": "/dev/xvda",
      "VolumeId": "vol-0535eb3c8013b3ca0",
      "DeleteOnTermination": true
    }
  ],
  "chain_of_custody_custodian": "AWS-Cloud-DFIR-Automated-Pipeline",
  "ebs_forensic_snapshots": [
    {
      "OriginalSnapshotId": "snap-03e8e49ae8db7d02c",
      "VaultSnapshotId": "snap-08fe440b5b1210946",
      "VolumeId": "vol-0535eb3c8013b3ca0",
      "KmsKeyArn": "arn:aws:kms:us-east-2:195275680107:key/08da40b7-d668-47d9-8b2f-c0afce51d31f"
    }
  ],
  "completed_stages": [
    "LiveVolatile",
    "NetworkQuarantine",
    "EBSSnapshots",
    "KMSEncryption",
    "ForensicAnalysis"
  ]
}
```

---

## 6. Threat Mapping to MITRE ATT&CK Matrix

Indicators of compromise identified during live artifact correlation were mapped against the MITRE ATT&CK Enterprise Matrix:

| Technique Identifier | Technique Name | MITRE Tactic | Observed Evidence in Host Artifacts |
| :--- | :--- | :--- | :--- |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | External socket connections mapped to Tor exit relay endpoints |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion | Audit checks verifying unlinked process execution in memory |
| T1053.003 | Scheduled Task/Job: Cron | Persistence | Scheduled task enumeration across `/etc/cron*` and systemd timers |
| T1059.004 | Unix Shell | Execution | In-memory interactive command execution history |

---

## 7. Lessons Learned and Remediation Actions

1. Operational Memory Constraints:
   * Finding: On Amazon Linux 2023, the default `/tmp` filesystem is configured as a `tmpfs` RAM disk with a 457 MB size ceiling, causing large physical memory dumps to encounter disk space exhaustion.
   * Action Implemented: Pipeline was updated to stage all volatile extraction operations in `/var/tmp` on the root NVMe block device, which provides over 6.3 GB of persistent scratch space.
2. Multipart KMS Decryption Authorization:
   * Finding: AWS CLI multipart uploads exceeding 16 MB against KMS-encrypted S3 buckets require `kms:Decrypt` permissions to validate multipart chunk signatures.
   * Action Implemented: The IAM role `cloud-dfir-orchestrator-target-ec2-role` was updated with `kms:Decrypt` and `s3:AbortMultipartUpload` permissions.
3. Recommended Immediate Host Remediation:
   * Maintain `Production-App-Server-Compromised` in the Quarantine Security Group until forensic sign-off is completed.
   * Terminate the host after snapshot retention validation to ensure complete eradication.
   * Rotate any IAM credentials associated with the host instance profile.
