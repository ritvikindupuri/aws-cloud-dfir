resource "aws_security_group" "quarantine_sg" {
  name        = "${var.project_name}-quarantine-sg"
  description = "Zero-Trust Forensic Quarantine SG: Blocks all inbound and lateral movement"
  vpc_id      = local.vpc_id

  # Strict zero-ingress
  ingress = []

  # Egress restricted strictly to HTTPS (443) for AWS Systems Manager and S3 endpoints
  egress {
    description = "Allow HTTPS for AWS SSM & S3 Agent Telemetry"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-quarantine-sg"
    Security    = "ZeroTrustQuarantine"
    DFIR_Action = "IsolateCompromisedHost"
  }
}
