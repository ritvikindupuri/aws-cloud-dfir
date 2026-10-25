resource "aws_sfn_state_machine" "cloud_dfir_pipeline" {
  name     = "${var.project_name}-state-machine"
  role_arn = aws_iam_role.step_functions_role.arn

  definition = jsonencode({
    Comment = "RFC 3227 AWS Cloud DFIR Orchestration Pipeline (Volatile State -> RAM -> Isolation -> EBS Snapshot -> Re-encryption -> Volatility Analysis)"
    StartAt = "TriggerLiveCapture"
    States = {
      TriggerLiveCapture = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.trigger_triage.arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "incident_id.$"              = "$.Payload.incident_id"
          "instance_id.$"              = "$.Payload.instance_id"
          "command_id.$"               = "$.Payload.command_id"
          "original_security_groups.$" = "$.Payload.original_security_groups"
          "attached_volumes.$"         = "$.Payload.attached_volumes"
          "evidence_bucket.$"          = "$.Payload.evidence_bucket"
        }
        Next = "WaitDuringVolatileAcquisition"
      }

      WaitDuringVolatileAcquisition = {
        Type    = "Wait"
        Seconds = 30
        Next    = "EnforceNetworkQuarantine"
      }

      EnforceNetworkQuarantine = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.isolate_instance.arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "incident_id.$"       = "$.Payload.incident_id"
          "instance_id.$"       = "$.Payload.instance_id"
          "quarantine_sg_id.$"  = "$.Payload.quarantine_sg_id"
          "status.$"            = "$.Payload.status"
          "attached_volumes.$"  = "$.Payload.attached_volumes"
        }
        Next = "SnapshotEBSVolumes"
      }

      SnapshotEBSVolumes = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.snapshot_ebs.arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "incident_id.$"   = "$.Payload.incident_id"
          "instance_id.$"   = "$.Payload.instance_id"
          "snapshots.$"     = "$.Payload.snapshots"
        }
        Next = "ReencryptForensicsVault"
      }

      ReencryptForensicsVault = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.reencrypt_evidence.arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "incident_id.$"            = "$.Payload.incident_id"
          "instance_id.$"            = "$.Payload.instance_id"
          "reencrypted_snapshots.$"  = "$.Payload.reencrypted_snapshots"
          "evidence_bucket.$"        = "$.Payload.evidence_bucket"
        }
        Next = "TriggerForensicAnalysis"
      }

      TriggerForensicAnalysis = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.run_volatility.arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "incident_id.$"        = "$.Payload.incident_id"
          "status.$"             = "$.Payload.status"
          "report_s3_prefix.$"   = "$.Payload.report_s3_prefix"
        }
        Next = "ForensicInvestigationComplete"
      }

      ForensicInvestigationComplete = {
        Type = "Succeed"
      }
    }
  })

  tags = {
    Name     = "${var.project_name}-state-machine"
    Standard = "RFC-3227-OrderOfVolatility"
  }
}
