# Terraform Deployment for Bank Application on AWS EC2 Windows

This Terraform project provisions an AWS EC2 Windows instance to host the Bank Application. It installs the required packages (Python3, Git, Chocolatey) and clones the Bank Application repository.

## Files

- **main.tf:**  
  Contains the AWS provider configuration and defines the EC2 instance resource with a remote-exec provisioner that runs PowerShell commands to install prerequisites, clone the repository, and start the application.

- **variables.tf:**  
  Defines variables for AWS region, AMI ID, instance type, key name, Windows username, and password.

- **outputs.tf:**  
  Outputs the public IP address of the provisioned EC2 instance.

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
   Replace `ami-xxxxxxxx` with the appropriate Windows AMI ID (for example, Windows Server 2019 Base), `your-key-name` with your AWS key pair name, and `your-instance-password` with the Administrator password for the instance.

4. **Apply the Terraform configuration:**
   ```sh
   terraform apply -var "ami_id=ami-xxxxxxxx" -var "key_name=your-key-name" -var "instance_password=your-instance-password"
   ```
   Confirm the prompt to deploy the resources.

5. **Access the Instance:**
   Once deployed, the public IP of the instance will be output. Use Remote Desktop (RDP) to connect to the instance:
   ```sh
   mstsc /v:<instance_public_ip>
   ```
   Log in using the username specified in `instance_username` (default is `Administrator`) and the provided password.
