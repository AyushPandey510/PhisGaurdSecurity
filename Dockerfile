FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy all files
COPY . .

# Install dependencies
RUN pip install -r requirements.txt

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "app.py"]