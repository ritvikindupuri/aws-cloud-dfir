resource "aws_ssm_document" "live_volatile_acquisition" {
  name          = "CloudDFIR-LiveVolatileAcquisition"
  document_type = "Command"
  document_format = "YAML"

  content = file("${path.module}/../ssm/live_volatile_acquisition.yaml")

  tags = {
    Name     = "CloudDFIR-LiveVolatileAcquisition"
    Security = "RFC-3227-OrderOfVolatility"
  }
}
