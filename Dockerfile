# Use the official Python 3.11 slim image for a lightweight footprint
FROM python:3.11-slim

# Set metadata
LABEL maintainer="VigilEdge Project"
LABEL description="VigilEdge Web Application Firewall (WAF)"

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for some Python packages (e.g. psutil, bcrypt)
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements first to leverage Docker cache
COPY "project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/requirements.txt" ./requirements.txt

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire WAF source code into the container
COPY "project-null-2.0/vigiledge-collage-project--main/VigilEdge/waf/" /app/waf/

# Expose the standard WAF port
EXPOSE 8000

# Set essential environment variables
ENV PYTHONPATH=/app/waf
ENV HOST=0.0.0.0
ENV PORT=8000
# Tell Python to run in unbuffered mode (better for Docker logs)
ENV PYTHONUNBUFFERED=1

# Change working directory to where the main entry point is located
WORKDIR /app/waf

# Command to run the WAF
CMD ["python", "main_new.py"]
