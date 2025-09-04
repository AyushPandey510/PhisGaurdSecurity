import requests
import hashlib
import re
import os
from typing import Tuple, List, Optional, Dict, Any

# Load configuration from environment variables
HIBP_API_URL = os.getenv("HIBP_API_URL", "https://api.pwnedpasswords.com/range/")
HIBP_EMAIL_API_URL = os.getenv("HIBP_EMAIL_API_URL", "https://haveibeenpwned.com/api/v3/breachedaccount/")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 10))
HIBP_API_KEY = os.getenv("HIBP_API_KEY")

def check_email_breach(email: str) -> Tuple[bool, int, List[str], Optional[str]]:
    """
    Check if email has been involved in known data breaches.
    Returns (breached, breach_count, breaches_list)
    """
    try:
        # Use Have I Been Pwned API
        # Note: This is a simplified implementation. In production, you'd want to use
        # the official HIBP API with proper rate limiting and API keys if available.

        # For demo purposes, we'll simulate a basic check
        # In a real implementation, you'd call: https://haveibeenpwned.com/api/v3/breachedaccount/{email}

        # This is a placeholder implementation
        return False, 0, []

    except Exception as e:
        return False, 0, [], f"Error checking email breach: {str(e)}"

def check_password_breach(password: str) -> Tuple[bool, int]:
    """
    Check if password has been compromised using k-anonymity.
    Returns (breached, breach_count)
    """
    try:
        # Use Have I Been Pwned password API with k-anonymity
        # Hash the password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        # Take first 5 characters for the API call
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Make API request
        response = requests.get(f"{HIBP_API_URL}{prefix}", timeout=REQUEST_TIMEOUT)

        if response.status_code == 200:
            # Check if our hash suffix is in the response
            lines = response.text.split('\n')
            for line in lines:
                if line.strip():
                    hash_suffix, count = line.split(':')
                    if hash_suffix.strip() == suffix:
                        return True, int(count.strip())

            return False, 0
        else:
            # Return consistent format even on API error
            return False, 0

    except requests.exceptions.RequestException as e:
        # Return consistent format even on request error
        return False, 0
    except Exception as e:
        # Return consistent format even on unexpected error
        return False, 0

def check_password_strength(password: str) -> Tuple[int, List[str]]:
    """
    Basic password strength checker.
    Returns (strength_score, feedback)
    """
    score = 0
    feedback = []

    # Length check
    if len(password) >= 8:
        score += 20
    else:
        feedback.append("Password should be at least 8 characters long")

    if len(password) >= 12:
        score += 10

    # Character variety checks
    if re.search(r'[a-z]', password):
        score += 15
    else:
        feedback.append("Include lowercase letters")

    if re.search(r'[A-Z]', password):
        score += 15
    else:
        feedback.append("Include uppercase letters")

    if re.search(r'\d', password):
        score += 15
    else:
        feedback.append("Include numbers")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 15
    else:
        feedback.append("Include special characters")

    # Common patterns
    common_patterns = ['123456', 'password', 'qwerty', 'abc123', 'admin']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 20
        feedback.append("Avoid common patterns")

    return min(100, max(0, score)), feedback

def comprehensive_security_check(email: Optional[str] = None, password: Optional[str] = None) -> Dict[str, Any]:
    """
    Comprehensive security check combining breach and strength analysis.
    """
    results = {
        "email_check": None,
        "password_breach_check": None,
        "password_strength_check": None,
        "overall_risk": "unknown"
    }

    if email:
        try:
            breached, count, breaches = check_email_breach(email)
            results["email_check"] = {
                "breached": breached,
                "breach_count": count,
                "breaches": breaches
            }
        except Exception as e:
            results["email_check"] = {"error": str(e)}

    if password:
        try:
            # Check for breaches
            breached, count = check_password_breach(password)
            results["password_breach_check"] = {
                "breached": breached,
                "breach_count": count
            }

            # Check strength
            strength, feedback = check_password_strength(password)
            results["password_strength_check"] = {
                "score": strength,
                "feedback": feedback
            }
        except Exception as e:
            results["password_breach_check"] = {"error": str(e)}

    # Calculate overall risk
    risk_score = 0

    if results["email_check"] and results["email_check"].get("breached"):
        risk_score += 40

    if results["password_breach_check"] and results["password_breach_check"].get("breached"):
        risk_score += 30

    if results["password_strength_check"]:
        strength_score = results["password_strength_check"].get("score", 0)
        risk_score += max(0, 30 - strength_score)

    if risk_score >= 70:
        results["overall_risk"] = "high"
    elif risk_score >= 40:
        results["overall_risk"] = "medium"
    elif risk_score >= 20:
        results["overall_risk"] = "low"
    else:
        results["overall_risk"] = "very_low"

    return results
