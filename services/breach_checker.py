import requests
import hashlib
import re
import os
import json
from typing import Tuple, List, Optional, Dict, Any

# Load configuration from environment variables
BREACH_DATA_FILE = os.getenv("BREACH_DATA_FILE", "breaches.json")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 10))

# Global variables for breach data
breach_data = None
password_hashes = {}
email_breaches = {}

def load_breach_data():
    """
    Load breach data from local JSON file and create efficient lookup structures.
    """
    global breach_data, password_hashes, email_breaches

    if breach_data is not None:
        print(f"Breach data already loaded: {len(breach_data)} records, {len(email_breaches)} emails")
        return  # Already loaded

    try:
        print(f"Loading breach data from: {BREACH_DATA_FILE}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"File exists: {os.path.exists(BREACH_DATA_FILE)}")
        print(f"Absolute path: {os.path.abspath(BREACH_DATA_FILE)}")

        if not os.path.exists(BREACH_DATA_FILE):
            print(f"Warning: Breach data file '{BREACH_DATA_FILE}' not found. Using empty dataset.")
            breach_data = []
            return

        with open(BREACH_DATA_FILE, 'r', encoding='utf-8') as f:
            breach_data = json.load(f)

        print(f"Successfully loaded {len(breach_data)} records from JSON")

        # Create efficient lookup structures
        password_hashes = {}
        email_breaches = {}

        email_count = 0
        password_count = 0

        for entry in breach_data:
            # Handle password hashes (create SHA-1 from plain text passwords)
            if 'password' in entry:
                password = entry['password']
                if password:  # Only hash non-empty passwords
                    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
                    count = entry.get('count', 1)
                    password_hashes[sha1_hash] = count
                    password_count += 1

            # Handle email breaches
            if 'email' in entry:
                email = entry['email'].lower()
                if email not in email_breaches:
                    email_breaches[email] = []
                email_breaches[email].append({
                    'breach_name': entry.get('source', 'Unknown'),
                    'breach_date': entry.get('breach_date', 'Unknown'),
                    'description': entry.get('description', ''),
                    'data_classes': entry.get('data_classes', [])
                })
                email_count += 1

        print(f"Created lookup structures: {len(password_hashes)} password hashes, {len(email_breaches)} unique emails")
        print(f"Processed {email_count} email entries, {password_count} password entries")

    except Exception as e:
        print(f"Error loading breach data: {str(e)}")
        import traceback
        traceback.print_exc()
        breach_data = []

def check_email_breach(email: str) -> Tuple[bool, int, List[str], Optional[str]]:
    """
    Check if email has been involved in known data breaches using local dataset.
    Returns (breached, breach_count, breaches_list, error_message)
    """
    try:
        # Load breach data if not already loaded
        load_breach_data()

        # Normalize email for lookup
        normalized_email = email.lower().strip()

        # Check if email exists in breach data
        if normalized_email in email_breaches:
            breaches = email_breaches[normalized_email]
            breach_count = len(breaches)
            breach_names = [breach['breach_name'] for breach in breaches]
            return True, breach_count, breach_names, None

        # If the email has @test.com domain (converted by extension for testing),
        # also check the @example.com version
        if '@test.com' in normalized_email:
            example_email = normalized_email.replace('@test.com', '@example.com')
            if example_email in email_breaches:
                breaches = email_breaches[example_email]
                breach_count = len(breaches)
                breach_names = [breach['breach_name'] for breach in breaches]
                return True, breach_count, breach_names, None

        return False, 0, [], None

    except Exception as e:
        return False, 0, [], f"Error checking email breach: {str(e)}"

def check_password_breach(password: str) -> Tuple[bool, int]:
    """
    Check if password has been compromised using local breach dataset.
    Returns (breached, breach_count)
    """
    try:
        # Load breach data if not already loaded
        load_breach_data()

        # Hash the password with SHA-1 (same as HIBP)
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        # Check if hash exists in our local dataset
        if sha1_hash in password_hashes:
            count = password_hashes[sha1_hash]
            return True, count

        return False, 0

    except Exception as e:
        # Return consistent format even on error
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
            breached, count, breaches, error_msg = check_email_breach(email)
            if error_msg:
                results["email_check"] = {"error": error_msg}
            else:
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
