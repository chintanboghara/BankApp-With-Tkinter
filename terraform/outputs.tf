output "instance_public_ip" {
  description = "Public IP address of the EC2 Windows instance"
  value       = aws_instance.bank_app_instance.public_ip
}
