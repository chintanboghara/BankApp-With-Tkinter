# Terraform Deployment for Bank Application on AWS EC2 Windows

This Terraform configuration provisions an AWS EC2 Windows instance to run the production-ready Bank Application. It installs Python3, Git, and Chocolatey, then clones the application repository and starts the application.

## Files

- **main.tf:**  
  Defines the EC2 instance resource and provisions it using PowerShell commands.
  
- **variables.tf:**  
  Contains variable definitions for AWS region, AMI ID, instance type, key pair, and Windows credentials.
  
- **outputs.tf:**  
  Outputs the public IP address of the provisioned instance.

## Deployment Steps

1. **Navigate to the Terraform directory:**
   ```sh
   cd terraform
   ```

2. **Initialize Terraform:**
   ```sh
   terraform init
   ```

3. **Plan the deployment:**
   ```sh
   terraform plan -var "ami_id=ami-xxxxxxxx" -var "key_name=your-key-name" -var "instance_password=your-instance-password"
   ```
   Replace:
   - `ami-xxxxxxxx` with the Windows AMI ID (e.g., Windows Server 2019 Base),
   - `your-key-name` with your AWS key pair name,
   - `your-instance-password` with the Administrator password.

4. **Apply the configuration:**
   ```sh
   terraform apply -var "ami_id=ami-xxxxxxxx" -var "key_name=your-key-name" -var "instance_password=your-instance-password"
   ```
   Confirm when prompted.

5. **Connect via RDP:**
   - Retrieve the instance public IP from Terraform outputs or the AWS Console.
   - Open the Remote Desktop Connection client (`mstsc` on Windows) and connect using:
     ```sh
     mstsc /v:<instance_public_ip>
     ```
   - Log in with the username specified (default is `Administrator`) and the provided password.
