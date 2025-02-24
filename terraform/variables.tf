variable "aws_region" {
  description = "AWS region to deploy in"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for the Windows instance (e.g., Windows Server 2019 Base)"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "key_name" {
  description = "Name of the AWS key pair for the instance"
  type        = string
}

variable "instance_username" {
  description = "Username for the Windows instance (typically Administrator)"
  type        = string
  default     = "Administrator"
}

variable "instance_password" {
  description = "Password for the Windows instance"
  type        = string
}
