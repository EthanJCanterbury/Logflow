
# LogFlow - Open Source Error and Log Management

LogFlow is a modern, open-source error tracking and log management system for developers. It provides real-time error tracking, structured logging, and performance metrics to help you debug your applications effectively.

## Features

- **Real-time Error Tracking**: Capture and monitor errors with detailed stack traces
- **Structured Logging**: Collect and search through logs with powerful filtering
- **Simple Integration**: Easy to integrate with any application using lightweight SDKs or API
- **Team Collaboration**: Work together to resolve issues
- **Performance Metrics**: Track application performance
- **Open Source**: Free and community-driven

## Getting Started

### Prerequisites

- Python 3.11 or higher
- PostgreSQL database (optional, defaults to SQLite)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/logflow.git
cd logflow
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set environment variables (optional):

```bash
export SECRET_KEY="your-secret-key"
export DATABASE_URL="postgresql://user:password@localhost/logflow"
```

4. Run the application:

```bash
python main.py
```

### Docker Setup

1. Build the Docker image:

```bash
docker build -t logflow .
```

2. Run the container:

```bash
docker run -p 5000:80 -e DATABASE_URL=postgresql://user:password@host/logflow -e SECRET_KEY=your-secret-key logflow
```

## API Usage

### Logging Errors

```python
import requests
import json

API_KEY = 'your-project-api-key'
API_URL = 'https://your-logflow-instance.com/api/errors'

# Log an error
error_response = requests.post(
    API_URL,
    headers={
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY
    },
    json={
        'message': 'Failed to process payment',
        'type': 'PaymentError',
        'metadata': {
            'order_id': 'ORD-12345',
            'amount': 99.99
        }
    }
)
```

### Logging Messages

```python
import requests

API_KEY = 'your-project-api-key'
API_URL = 'https://your-logflow-instance.com/api/logs'

# Log a message
response = requests.post(
    API_URL,
    headers={
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY
    },
    json={
        'message': 'User logged in',
        'level': 'INFO',
        'metadata': {
            'user_id': 123, 
            'role': 'admin'
        }
    }
)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
