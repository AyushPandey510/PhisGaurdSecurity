import pytest
import json
from unittest.mock import Mock, patch
from app import app, settings
from utils.config import Settings

class TestApp:
    """Test cases for the main Flask application"""

    def setup_method(self):
        """Set up test client"""
        self.app = app.test_client()
        self.app.testing = True

    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.app.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'service' in data

    def test_extension_health_endpoint(self):
        """Test extension health check endpoint"""
        response = self.app.get('/extension/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['extension_support'] == True

    def test_root_endpoint(self):
        """Test root endpoint"""
        response = self.app.get('/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert 'version' in data
        assert 'endpoints' in data

    @patch('app.check_url')
    def test_check_url_endpoint_success(self, mock_check_url):
        """Test URL check endpoint with valid data"""
        mock_check_url.return_value = (25, ["Test risk factor"])

        # Test with extension origin (should bypass API key)
        response = self.app.post(
            '/check-url',
            json={'url': 'https://example.com'},
            headers={'Origin': 'chrome-extension://test'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'url' in data
        assert 'risk_score' in data
        assert 'recommendation' in data

    def test_check_url_endpoint_missing_url(self):
        """Test URL check endpoint with missing URL"""
        response = self.app.post(
            '/check-url',
            json={},
            headers={'Origin': 'chrome-extension://test'}
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    def test_check_url_endpoint_invalid_url(self):
        """Test URL check endpoint with invalid URL"""
        response = self.app.post(
            '/check-url',
            json={'url': 'not-a-valid-url'},
            headers={'Origin': 'chrome-extension://test'}
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    def test_api_key_required_for_non_extension(self):
        """Test that API key is required for non-extension requests"""
        response = self.app.post(
            '/check-url',
            json={'url': 'https://example.com'}
        )
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert 'API key' in data['error']

    def test_invalid_api_key(self):
        """Test invalid API key"""
        response = self.app.post(
            '/check-url',
            json={'url': 'https://example.com'},
            headers={'X-API-Key': 'invalid-key'}
        )
        assert response.status_code == 401

    def test_404_handler(self):
        """Test 404 error handler"""
        response = self.app.get('/nonexistent-endpoint')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data
        assert data['extension_support'] == True

    def test_cors_headers(self):
        """Test CORS headers are set correctly"""
        response = self.app.get('/health', headers={'Origin': 'chrome-extension://test'})
        assert response.status_code == 200
        assert 'Access-Control-Allow-Origin' in response.headers
        assert response.headers['Access-Control-Allow-Origin'] == 'chrome-extension://test'

class TestInputValidation:
    """Test input validation functions"""

    def test_sanitize_input(self):
        """Test input sanitization"""
        from app import sanitize_input

        # Test normal input
        assert sanitize_input("hello world") == "hello world"

        # Test XSS attempt
        assert sanitize_input("<script>alert('xss')</script>") == ""

        # Test empty input
        assert sanitize_input("") == ""

        # Test None input
        assert sanitize_input(None) == ""

    def test_validate_url(self):
        """Test URL validation"""
        from app import validate_url

        # Valid URL
        url, error = validate_url("https://example.com")
        assert url == "https://example.com"
        assert error is None

        # URL without protocol
        url, error = validate_url("example.com")
        assert url == "https://example.com"
        assert error is None

        # Invalid URL
        url, error = validate_url("not-a-url")
        assert url is None
        assert error is not None

        # Empty URL
        url, error = validate_url("")
        assert url is None
        assert error is not None

    def test_validate_email(self):
        """Test email validation"""
        from app import validate_email

        # Valid email
        email, error = validate_email("test@example.com")
        assert email == "test@example.com"
        assert error is None

        # Invalid email
        email, error = validate_email("not-an-email")
        assert email is None
        assert error is not None

        # Empty email
        email, error = validate_email("")
        assert email is None
        assert error is not None

class TestConfiguration:
    """Test configuration management"""

    def test_settings_validation(self):
        """Test settings validation"""
        # Valid settings
        settings = Settings(
            secret_key="a" * 32,
            api_key="a" * 16
        )
        assert settings.secret_key == "a" * 32
        assert settings.api_key == "a" * 16

    def test_invalid_secret_key(self):
        """Test invalid secret key validation"""
        with pytest.raises(ValueError):
            Settings(secret_key="short", api_key="a" * 16)

    def test_invalid_api_key(self):
        """Test invalid API key validation"""
        with pytest.raises(ValueError):
            Settings(secret_key="a" * 32, api_key="short")

    def test_invalid_cors_origin(self):
        """Test invalid CORS origin validation"""
        with pytest.raises(ValueError):
            Settings(
                secret_key="a" * 32,
                api_key="a" * 16,
                cors_origins=["invalid-origin"]
            )

    def test_invalid_log_level(self):
        """Test invalid log level validation"""
        with pytest.raises(ValueError):
            Settings(
                secret_key="a" * 32,
                api_key="a" * 16,
                log_level="INVALID"
            )

if __name__ == '__main__':
    pytest.main([__file__])