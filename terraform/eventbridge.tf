# ==============================================================================
# Real-Time EventBridge Trigger for High-Severity GuardDuty EC2 Instance Findings
# (Zero simulation: Triggers natively on genuine AWS security telemetry)
# ==============================================================================

resource "aws_cloudwatch_event_rule" "guardduty_high_severity" {
  name        = "${var.project_name}-guardduty-finding"
  description = "Captures high-severity Amazon GuardDuty EC2 instance findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        7, 7.0, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9,
        8, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9
      ]
      resource = {
        resourceType = ["Instance"]
      }
    }
  })

  tags = {
    Security = "RealTimeThreatTrigger"
  }
}

resource "aws_cloudwatch_event_target" "step_function_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_high_severity.name
  target_id = "TriggerCloudDFIRStepFunction"
  arn       = aws_sfn_state_machine.cloud_dfir_pipeline.arn
  role_arn  = aws_iam_role.eventbridge_sfn_role.arn
}

resource "aws_iam_role" "eventbridge_sfn_role" {
  name = "${var.project_name}-eventbridge-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_start_execution" {
  name = "AllowStartDFIRExecution"
  role = aws_iam_role.eventbridge_sfn_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "states:StartExecution"
        Resource = aws_sfn_state_machine.cloud_dfir_pipeline.arn
      }
    ]
  })
}
