provider "aws" {
  region = var.aws_region
}

resource "aws_instance" "bank_app_instance" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  tags = {
    Name = "BankAppInstance"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update -y",
      "sudo apt-get install -y python3 python3-tk git",
      # Clone your repository or copy the BankAppWithTkinter.py file to the instance.
      "git clone https://github.com/your-username/BankAppProject.git /home/ubuntu/bank_app",
      # (Optional) Run the Bank Application. Note: Running a GUI app on a headless server may require additional configuration.
      "cd /home/ubuntu/bank_app && nohup python3 BankAppWithTkinter.py &"
    ]
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.private_key_path)
      host        = self.public_ip
    }
  }
}
