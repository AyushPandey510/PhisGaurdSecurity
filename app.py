from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from services.url_checker import check_url
from services.ssl_checker import check_ssl
from services.link_expander import expand_link
from services.breach_checker import check_password_breach, check_password_strength, comprehensive_security_check, load_breach_data
from utils.risk_scorer import RiskScorer, quick_risk_assessment
from utils.logger import get_security_logger
from utils.config import get_settings
from utils.health import get_health_checker
from utils.cache import get_cache
import os
import logging
import bleach
import validators
import traceback
import time
from email_validator import validate_email as validate_email_lib, EmailNotValidError
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get application settings
settings = get_settings()

app = Flask(__name__)

# Initialize security logger
security_logger = get_security_logger()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Disable Flask-Talisman for extension compatibility
# Add basic security headers manually
@app.after_request
def add_security_headers(response):
    """Add basic security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Configure CORS for Chrome extension communication
CORS(app, origins=settings.cors_origins, supports_credentials=True, methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"])

# Additional CORS configuration for extension requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = app.make_response('')
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-API-Key")
        return response

# Configuration from settings
app.config['DEBUG'] = settings.debug
app.config['SECRET_KEY'] = settings.secret_key
app.config['MAX_CONTENT_LENGTH'] = settings.max_content_length
app.config['PERMANENT_SESSION_LIFETIME'] = settings.permanent_session_lifetime
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching for security
app.config['API_KEY'] = settings.api_key
app.config['TIMEOUT'] = settings.request_timeout

# Force load breach data on startup
try:
    logger.info("Loading breach data on application startup...")
    load_breach_data()
    logger.info("Breach data loaded successfully")
except Exception as e:
    logger.error(f"Failed to load breach data on startup: {str(e)}")

# Security validation functions
def sanitize_input(text):
    """Sanitize input to prevent XSS and injection attacks"""
    if not isinstance(text, str):
        return ""
    return bleach.clean(text, tags=[], attributes={}, strip=True)

def validate_url(url):
    """Validate and normalize URL"""
    if not url or not isinstance(url, str):
        return None, "Invalid URL format"

    url = sanitize_input(url.strip())
    if not url:
        return None, "URL is required"

    # Use validators library for URL validation
    if not validators.url(url):
        return None, "Invalid URL format"

    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    return url, None

def validate_email(email):
    """Validate email format"""
    if not email or not isinstance(email, str):
        return None, "Invalid email format"

    email = sanitize_input(email.strip())
    if not email:
        return None, "Email is required"

    # Allow @example.com emails for testing purposes
    if email.endswith('@example.com'):
        # Basic email format validation for @example.com
        import re
        if re.match(r'^[a-zA-Z0-9._%+-]+@example\.com$', email):
            return email, None
        else:
            return None, "Invalid email format"

    try:
        valid = validate_email_lib(email)
        return valid.email, None
    except EmailNotValidError as e:
        return None, str(e)

def validate_password_strength(password):
    """Validate password meets minimum requirements"""
    if not password or not isinstance(password, str):
        return False, "Password is required"

    password = sanitize_input(password)
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit"
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter"

    return True, None

def log_security_event(event_type, details, ip_address, level='WARNING'):
    """Log security-related events in structured format"""
    security_logger.log_security_event(
        event_type=event_type,
        details=details,
        ip_address=ip_address,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        endpoint=request.path,
        level=level
    )

def require_api_key(f):
    """Decorator to require API key for endpoints"""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip API key check for extension requests
        origin = request.headers.get('Origin', '')
        user_agent = request.headers.get('User-Agent', '')

        # Check for extension requests
        if (origin.startswith('chrome-extension://') or
            'Chrome' in user_agent and 'Extension' in user_agent):
            return f(*args, **kwargs)

        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key or api_key != app.config['API_KEY']:
            log_security_event("INVALID_API_KEY", "Missing or invalid API key", request.remote_addr)
            return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "message": "PhisGuard Backend API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "check_url": "/check-url",
            "check_ssl": "/check-ssl",
            "expand_link": "/expand-link",
            "check_breach": "/check-breach",
            "comprehensive_check": "/comprehensive-check"
        }
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint"""
    return jsonify({"status": "healthy", "service": "phisguard-backend"})

@app.route('/health/detailed', methods=['GET'])
def detailed_health_check():
    """Detailed health check with system and application metrics"""
    health_checker = get_health_checker()
    return jsonify(health_checker.get_full_health_report())

@app.route('/extension/health', methods=['GET'])
def extension_health_check():
    return jsonify({
        "status": "healthy",
        "service": "phisguard-backend",
        "extension_support": True,
        "cors_enabled": True,
        "supported_origins": ["chrome-extension://*"]
    })

@app.route('/check-url', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def check_url_endpoint():
    data = request.get_json()
    if not data:
        log_security_event("INVALID_REQUEST", "Missing request data", request.remote_addr)
        return jsonify({"error": "Request data is required"}), 400

    url = data.get('url')
    if not url:
        log_security_event("MISSING_URL", "URL parameter missing", request.remote_addr)
        return jsonify({"error": "URL is required"}), 400

    # Validate and sanitize URL
    validated_url, error = validate_url(url)
    if error:
        log_security_event("INVALID_URL", f"URL validation failed: {error}", request.remote_addr)
        return jsonify({"error": error}), 400

    try:
        risk_score, details = check_url(validated_url)
        return jsonify({
            "url": validated_url,
            "risk_score": risk_score,
            "details": details,
            "recommendation": "safe" if risk_score < 30 else "caution" if risk_score < 70 else "danger"
        })
    except Exception as e:
        logger.error(f"Error in check_url_endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/check-ssl', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def check_ssl_endpoint():
    data = request.get_json()
    if not data:
        log_security_event("INVALID_REQUEST", "Missing request data", request.remote_addr)
        return jsonify({"error": "Request data is required"}), 400

    url = data.get('url')
    if not url:
        log_security_event("MISSING_URL", "URL parameter missing", request.remote_addr)
        return jsonify({"error": "URL is required"}), 400

    # Validate and sanitize URL
    validated_url, error = validate_url(url)
    if error:
        log_security_event("INVALID_URL", f"URL validation failed: {error}", request.remote_addr)
        return jsonify({"error": error}), 400

    try:
        is_valid, details = check_ssl(validated_url)
        return jsonify({
            "url": validated_url,
            "ssl_valid": is_valid,
            "details": details
        })
    except Exception as e:
        logger.error(f"Error in check_ssl_endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/expand-link', methods=['POST'])
@limiter.limit("10 per minute")
@require_api_key
def expand_link_endpoint():
    data = request.get_json()
    if not data:
        log_security_event("INVALID_REQUEST", "Missing request data", request.remote_addr)
        return jsonify({"error": "Request data is required"}), 400

    url = data.get('url')
    if not url:
        log_security_event("MISSING_URL", "URL parameter missing", request.remote_addr)
        return jsonify({"error": "URL is required"}), 400

    # Validate and sanitize URL
    validated_url, error = validate_url(url)
    if error:
        log_security_event("INVALID_URL", f"URL validation failed: {error}", request.remote_addr)
        return jsonify({"error": error}), 400

    try:
        final_url, redirect_chain, analysis, error = expand_link(validated_url)
        if error:
            # Provide user-friendly error messages
            if "Connection refused" in error or "Failed to establish a new connection" in error:
                user_friendly_error = "Unable to connect to the URL. The website may be down or not responding."
            elif "timeout" in error.lower():
                user_friendly_error = "Request timed out. The website is taking too long to respond."
            elif "Invalid URL" in error:
                user_friendly_error = "The URL format is invalid."
            else:
                user_friendly_error = "Unable to expand the link. Please check if the URL is accessible."

            return jsonify({
                "error": user_friendly_error,
                "technical_details": error if app.config['DEBUG'] else None,
                "url": validated_url
            }), 400

        return jsonify({
            "original_url": validated_url,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "redirect_count": len(redirect_chain),
            "analysis": analysis
        })
    except Exception as e:
        logger.error(f"Error in expand_link_endpoint: {str(e)}")
        return jsonify({
            "error": "An unexpected error occurred while expanding the link.",
            "url": validated_url
        }), 500

@app.route('/check-breach', methods=['POST'])
@limiter.limit("5 per minute")  # Stricter limit for breach checks
@require_api_key
def check_breach_endpoint():
    data = request.get_json()
    if not data:
        log_security_event("INVALID_REQUEST", "Missing request data", request.remote_addr)
        return jsonify({"error": "Request data is required"}), 400

    email = data.get('email')
    password = data.get('password')

    if not email and not password:
        log_security_event("MISSING_CREDENTIALS", "Neither email nor password provided", request.remote_addr)
        return jsonify({"error": "Either email or password must be provided"}), 400

    # Validate email if provided
    if email:
        validated_email, error = validate_email(email)
        if error:
            log_security_event("INVALID_EMAIL", f"Email validation failed: {error}", request.remote_addr)
            return jsonify({"error": error}), 400
        email = validated_email

    # For breach checking, we only validate basic requirements (not full strength)
    # This allows checking if weak passwords have been breached
    if password:
        password = sanitize_input(password)
        if len(password) < 1:
            return jsonify({"error": "Password cannot be empty"}), 400
        # Skip full strength validation for breach checks - we want to check ALL passwords

    try:
        if password and not email:
            # Password-only check
            breached, count = check_password_breach(password)
            strength_score, feedback = check_password_strength(password)
            return jsonify({
                "password_check": {
                    "breached": breached,
                    "breach_count": count
                },
                "password_strength": {
                    "score": strength_score,
                    "feedback": feedback
                }
            })
        else:
            # Comprehensive check
            results = comprehensive_security_check(email, password)
            return jsonify(results)
    except Exception as e:
        logger.error(f"Error in check_breach_endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/comprehensive-check', methods=['POST'])
@limiter.limit("5 per minute")  # Stricter limit for comprehensive checks
@require_api_key
def comprehensive_check_endpoint():
    data = request.get_json()
    if not data:
        log_security_event("INVALID_REQUEST", "Missing request data", request.remote_addr)
        return jsonify({"error": "Request data is required"}), 400

    url = data.get('url')
    if not url:
        log_security_event("MISSING_URL", "URL parameter missing", request.remote_addr)
        return jsonify({"error": "URL is required"}), 400

    email = data.get('email')
    password = data.get('password')

    # Validate URL
    validated_url, error = validate_url(url)
    if error:
        log_security_event("INVALID_URL", f"URL validation failed: {error}", request.remote_addr)
        return jsonify({"error": error}), 400

    # Validate email if provided
    if email:
        validated_email, error = validate_email(email)
        if error:
            log_security_event("INVALID_EMAIL", f"Email validation failed: {error}", request.remote_addr)
            return jsonify({"error": error}), 400
        email = validated_email

    # Validate password strength if provided
    if password:
        valid, error = validate_password_strength(password)
        if not valid:
            log_security_event("WEAK_PASSWORD", f"Password validation failed: {error}", request.remote_addr)
            return jsonify({"error": error}), 400

    try:
        scorer = RiskScorer()

        # Gather results from all checkers
        url_results = None
        ssl_results = None
        link_results = None
        breach_results = None

        # URL check
        url_risk, url_details = check_url(validated_url)
        url_results = {
            "risk_score": url_risk,
            "details": url_details,
            "recommendation": "safe" if url_risk < 30 else "caution" if url_risk < 70 else "danger"
        }

        # SSL check
        ssl_valid, ssl_details = check_ssl(validated_url)
        ssl_results = {"is_valid": ssl_valid, **ssl_details}

        # Link expansion check
        final_url, redirect_chain, link_error = expand_link(validated_url)
        link_results = {
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "error": link_error
        }

        # Breach check (if credentials provided)
        if email or password:
            breach_results = comprehensive_security_check(email, password)

        # Calculate overall risk
        assessment = scorer.calculate_overall_risk(
            url_results=url_results,
            ssl_results=ssl_results,
            link_results=link_results,
            breach_results=breach_results
        )

        return jsonify({
            "url": validated_url,
            "assessment": assessment,
            "individual_checks": {
                "url_check": url_results,
                "ssl_check": ssl_results,
                "link_expansion": link_results,
                "breach_check": breach_results
            }
        })

    except Exception as e:
        logger.error(f"Error in comprehensive_check_endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.before_request
def before_request():
    """Log incoming requests and start timing"""
    request.start_time = time.time()

@app.after_request
def after_request(response):
    """Log response details and timing"""
    if hasattr(request, 'start_time'):
        duration = time.time() - request.start_time
        security_logger.log_api_request(
            method=request.method,
            endpoint=request.path,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            status_code=response.status_code,
            duration=duration
        )

    # Add extension headers and CORS
    response.headers['X-Extension-Support'] = 'enabled'

    # Handle CORS for extension requests
    origin = request.headers.get('Origin', '')
    if origin.startswith('chrome-extension://') or not origin:
        response.headers['Access-Control-Allow-Origin'] = origin or '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-API-Key'
        response.headers['Access-Control-Allow-Credentials'] = 'true'

    return response

@app.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors with detailed logging"""
    error_details = {
        "error_type": "InternalServerError",
        "message": str(error),
        "traceback": traceback.format_exc()
    }

    security_logger.log_error(
        error_type="InternalServerError",
        message=str(error),
        traceback=traceback.format_exc(),
        ip_address=getattr(request, 'remote_addr', 'Unknown'),
        endpoint=getattr(request, 'path', 'Unknown')
    )

    # Return different error details based on debug mode
    if app.config['DEBUG']:
        return jsonify({
            "error": "Internal server error",
            "extension_support": True,
            "message": "An unexpected error occurred",
            "details": error_details
        }), 500
    else:
        return jsonify({
            "error": "Internal server error",
            "extension_support": True,
            "message": "An unexpected error occurred while processing the request"
        }), 500

@app.errorhandler(400)
def handle_bad_request(error):
    """Handle bad request errors"""
    security_logger.log_security_event(
        event_type="BadRequest",
        details={"error": str(error)},
        ip_address=getattr(request, 'remote_addr', 'Unknown'),
        user_agent=getattr(request, 'headers', {}).get('User-Agent', 'Unknown'),
        endpoint=getattr(request, 'path', 'Unknown'),
        level='WARNING'
    )

    return jsonify({
        "error": "Bad request",
        "extension_support": True,
        "message": "Invalid request format or parameters"
    }), 400

@app.errorhandler(404)
def handle_not_found(error):
    """Handle 404 errors"""
    security_logger.log_security_event(
        event_type="NotFound",
        details={"path": getattr(request, 'path', 'Unknown')},
        ip_address=getattr(request, 'remote_addr', 'Unknown'),
        user_agent=getattr(request, 'headers', {}).get('User-Agent', 'Unknown'),
        endpoint=getattr(request, 'path', 'Unknown'),
        level='INFO'
    )

    return jsonify({
        "error": "Not found",
        "extension_support": True,
        "message": "The requested resource was not found"
    }), 404

@app.errorhandler(429)
def handle_rate_limit_exceeded(error):
    """Handle rate limit exceeded errors"""
    log_security_event("RATE_LIMIT_EXCEEDED", "Too many requests", getattr(request, 'remote_addr', 'Unknown'))
    return jsonify({
        "error": "Too many requests",
        "extension_support": True,
        "message": "Rate limit exceeded. Please try again later."
    }), 429

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    """Catch-all handler for unexpected errors"""
    error_details = {
        "error_type": type(error).__name__,
        "message": str(error),
        "traceback": traceback.format_exc()
    }

    security_logger.log_error(
        error_type="UnexpectedError",
        message=str(error),
        traceback=traceback.format_exc(),
        ip_address=getattr(request, 'remote_addr', 'Unknown'),
        endpoint=getattr(request, 'path', 'Unknown')
    )

    if app.config['DEBUG']:
        return jsonify({
            "error": "Unexpected error",
            "extension_support": True,
            "message": "An unexpected error occurred",
            "details": error_details
        }), 500
    else:
        return jsonify({
            "error": "Unexpected error",
            "extension_support": True,
            "message": "An unexpected error occurred while processing the request"
        }), 500

if __name__ == '__main__':
    app.run(debug=settings.debug, host=settings.host, port=settings.port)
