# Use a base image with Python installed
FROM python:latest

# Set the working directory in the container
WORKDIR /app

# Install necessary packages
RUN apt-get update && \
    apt-get install -y python3-tk && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the application files into the container
COPY . .

# Set the entry point to run the application
CMD ["python", "BankAppWithTkinter.py"]
