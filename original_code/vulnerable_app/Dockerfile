# Vulnerable App Dockerfile
FROM python:3.10-slim

LABEL maintainer="VulnHunter Project"
LABEL description="Deliberately vulnerable Flask app for security education"

WORKDIR /app

# Install dependencies
COPY original_code/vulnerable_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY original_code/vulnerable_app/ .

# Create upload directory
RUN mkdir -p /tmp/uploads

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Warning message
RUN echo "WARNING: This is a deliberately vulnerable application!" > /etc/motd

# Run the application
CMD ["python", "app.py"]
