
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir "flask>=3.1.1" "flask-cors>=6.0.0" "flask-sqlalchemy>=3.1.1" "psycopg2-binary>=2.9.10" "werkzeug>=3.1.3" "flask-limiter>=3.5.0"

# Copy application code
COPY . .

# Set environment variables
ENV FLASK_APP=main.py
ENV FLASK_ENV=production

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "main.py"]
