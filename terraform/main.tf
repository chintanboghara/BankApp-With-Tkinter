provider "aws" {
  region = var.aws_region
}

resource "aws_instance" "bank_app_instance" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  tags = {
    Name = "BankAppInstanceWindows"
  }

  provisioner "remote-exec" {
    inline = [
      # Install Chocolatey
      "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))",
      # Install Python3 and Git via Chocolatey
      "choco install python3 -y",
      "choco install git -y",
      # Clone the repository
      "git clone https://github.com/chintanboghara/BankApp-With-Tkinter.git C:\\BankApp-With-Tkinter",
      # Launch the Bank Application (GUI visible via RDP)
      "Start-Process -FilePath 'python' -ArgumentList 'C:\\BankApp-With-Tkinter\\BankAppWithTkinter.py'"
    ]
    connection {
      type     = "winrm"
      host     = self.public_ip
      user     = var.instance_username
      password = var.instance_password
      https    = true
      insecure = true
    }
  }
}
