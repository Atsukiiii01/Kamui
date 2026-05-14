# Use a lightweight Python base image
FROM python:3.11-slim

# Install system dependencies (Nmap)
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the Kamui project files into the container
COPY . /app

# Install Kamui as a system package
RUN pip install --no-cache-dir -e .

# Ensure the container launches Kamui natively
ENTRYPOINT ["kamui"]