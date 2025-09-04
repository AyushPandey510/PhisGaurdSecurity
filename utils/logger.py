import logging
import json
import sys
from datetime import datetime
from typing import Dict, Any
import os

class SecurityLogger:
    """Enhanced security logging with structured JSON output"""

    def __init__(self):
        self.logger = logging.getLogger('phisguard.security')
        self.logger.setLevel(logging.INFO)

        # Remove any existing handlers
        self.logger.handlers.clear()

        # Create formatters
        json_formatter = JSONFormatter()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Console handler for development
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO)

        # File handler for production
        log_file = os.getenv('LOG_FILE', 'phisguard.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(json_formatter)
        file_handler.setLevel(logging.WARNING)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

        # Prevent duplicate logs
        self.logger.propagate = False

    def log_security_event(self, event_type: str, details: Dict[str, Any],
                          ip_address: str, user_agent: str = None,
                          endpoint: str = None, level: str = 'WARNING'):
        """Log security-related events with structured data"""

        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'ip_address': ip_address,
            'details': details,
            'user_agent': user_agent or 'Unknown',
            'endpoint': endpoint or 'Unknown',
            'severity': level
        }

        if level == 'ERROR':
            self.logger.error(f"Security event: {event_type}", extra=log_data)
        elif level == 'WARNING':
            self.logger.warning(f"Security event: {event_type}", extra=log_data)
        else:
            self.logger.info(f"Security event: {event_type}", extra=log_data)

    def log_api_request(self, method: str, endpoint: str, ip_address: str,
                       user_agent: str, status_code: int, duration: float):
        """Log API requests for monitoring"""

        self.logger.info("API Request", extra={
            'timestamp': datetime.utcnow().isoformat(),
            'method': method,
            'endpoint': endpoint,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'status_code': status_code,
            'duration_ms': round(duration * 1000, 2),
            'event_type': 'api_request'
        })

    def log_error(self, error_type: str, message: str, traceback: str = None,
                 ip_address: str = None, endpoint: str = None):
        """Log application errors"""

        self.logger.error(f"Application error: {error_type}", extra={
            'timestamp': datetime.utcnow().isoformat(),
            'error_type': error_type,
            'message': message,
            'traceback': traceback,
            'ip_address': ip_address or 'Unknown',
            'endpoint': endpoint or 'Unknown',
            'event_type': 'application_error'
        })

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""

    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, 'event_type'):
            log_entry['event_type'] = record.event_type
        if hasattr(record, 'ip_address'):
            log_entry['ip_address'] = record.ip_address
        if hasattr(record, 'details'):
            log_entry['details'] = record.details
        if hasattr(record, 'user_agent'):
            log_entry['user_agent'] = record.user_agent
        if hasattr(record, 'endpoint'):
            log_entry['endpoint'] = record.endpoint
        if hasattr(record, 'method'):
            log_entry['method'] = record.method
        if hasattr(record, 'status_code'):
            log_entry['status_code'] = record.status_code
        if hasattr(record, 'duration_ms'):
            log_entry['duration_ms'] = record.duration_ms

        return json.dumps(log_entry, default=str)

# Global security logger instance
security_logger = SecurityLogger()

def get_security_logger():
    """Get the global security logger instance"""
    return security_logger