import ssl
import socket
from datetime import datetime, timezone
import urllib.parse
import os

# Load configuration from environment variables
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 10))
SSL_VERIFY_CERTIFICATES = os.getenv("SSL_VERIFY_CERTIFICATES", "True").lower() == "true"

# Known Certificate Authorities (subset of major CAs)
KNOWN_CAS = {
    "DigiCert", "GlobalSign", "Let's Encrypt", "GoDaddy", "Comodo", "Entrust",
    "VeriSign", "Thawte", "GeoTrust", "RapidSSL", "SSL.com", "Sectigo",
    "Trustwave", "StartCom", "WoSign", "Symantec", "Network Solutions",
    "Amazon", "Google Trust Services", "Microsoft", "Apple", "Mozilla"
}

def check_ssl(url: str):
    """
    Advanced SSL certificate analysis with expiry alerts, issuer validation, and wildcard detection.
    Returns (is_valid, details_dict)
    """
    risk_score = 0
    risk_flags = []

    try:
        # Parse URL to get hostname and scheme
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme.lower()

        if not hostname:
            return False, {"error": "Invalid URL format", "risk_score": 100, "risk_flags": ["Invalid URL format"]}

        # Handle HTTP vs HTTPS
        if scheme == "http":
            return False, {
                "error": "HTTP connection (unencrypted)",
                "risk_score": 60,
                "risk_flags": ["⚠️ Connection is unencrypted (HTTP) - No SSL certificate to analyze"],
                "connection_type": "http",
                "recommendation": "Use HTTPS for secure communication"
            }

        # For HTTPS, proceed with SSL analysis
        if scheme != "https":
            return False, {
                "error": f"Unsupported protocol: {scheme}",
                "risk_score": 50,
                "risk_flags": [f"⚠️ Unsupported protocol: {scheme}"]
            }

        # Create SSL context
        context = ssl.create_default_context()
        if not SSL_VERIFY_CERTIFICATES:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Connect to the host
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return False, {
                "error": "No certificate found",
                "risk_score": 80,
                "risk_flags": ["❌ No SSL certificate found"],
                "connection_type": "https"
            }

        # Extract certificate details
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        details = {
            "subject": subject,
            "issuer": issuer,
            "version": cert.get("version"),
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "connection_type": "https",
            "risk_score": 0,
            "risk_flags": []
        }

        # === EXPIRY ANALYSIS ===
        not_after = cert.get("notAfter")
        if not_after:
            try:
                # Parse expiry date (handle timezone properly)
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)

                current_time = datetime.now(timezone.utc)
                is_expired = current_time > expiry_date

                if is_expired:
                    days_expired = (current_time - expiry_date).days
                    details["is_expired"] = True
                    details["days_since_expiry"] = days_expired
                    risk_flags.append(f"🚨 EXPIRED {days_expired} days ago")
                    risk_score += 40
                else:
                    days_until_expiry = (expiry_date - current_time).days
                    details["is_expired"] = False
                    details["days_until_expiry"] = days_until_expiry

                    if days_until_expiry <= 0:
                        risk_flags.append("🚨 Certificate expired!")
                        risk_score += 40
                    elif days_until_expiry <= 7:
                        risk_flags.append(f"⚠️ Expires in {days_until_expiry} days - CRITICAL")
                        risk_score += 30
                    elif days_until_expiry <= 30:
                        risk_flags.append(f"⚠️ Expires in {days_until_expiry} days - Renew soon")
                        risk_score += 10
                    else:
                        risk_flags.append(f"✅ Valid for {days_until_expiry} more days")
            except ValueError as e:
                risk_flags.append(f"⚠️ Could not parse certificate dates: {e}")
                risk_score += 5

        # === ISSUER VALIDATION ===
        subject_common_name = subject.get("commonName", "").lower()
        issuer_common_name = issuer.get("commonName", "").lower()
        issuer_org = issuer.get("organizationName", "").lower()

        # Check for self-signed certificates
        if subject_common_name == issuer_common_name:
            risk_flags.append("🚨 SELF-SIGNED certificate detected")
            risk_score += 40
            details["is_self_signed"] = True
        else:
            details["is_self_signed"] = False

        # Check if issuer is in known CAs
        issuer_known = any(ca.lower() in issuer_org or ca.lower() in issuer_common_name for ca in KNOWN_CAS)
        if not issuer_known and issuer_org:
            risk_flags.append(f"⚠️ Unknown Certificate Authority: {issuer_org}")
            risk_score += 15
        elif issuer_known:
            risk_flags.append(f"✅ Issued by trusted CA: {issuer_org}")

        # === WILDCARD CERTIFICATE DETECTION ===
        if subject_common_name.startswith("*."):
            risk_flags.append("⚠️ WILDCARD certificate detected - ensure all subdomains are trusted")
            risk_score += 10
            details["is_wildcard"] = True
        else:
            details["is_wildcard"] = False

        # === ADDITIONAL SECURITY CHECKS ===
        # Check certificate version (should be 3)
        cert_version = cert.get("version")
        if cert_version and cert_version < 3:
            risk_flags.append("⚠️ Outdated certificate version")
            risk_score += 5

        # Check key size (if available)
        public_key = cert.get("publicKey")
        if public_key:
            try:
                key_size = public_key.key_size
                if key_size < 2048:
                    risk_flags.append(f"⚠️ Weak key size: {key_size} bits")
                    risk_score += 10
                else:
                    risk_flags.append(f"✅ Strong key size: {key_size} bits")
            except:
                pass  # Key size not available

        # === FINAL RISK ASSESSMENT ===
        details["risk_score"] = min(risk_score, 100)
        details["risk_flags"] = risk_flags

        # Overall validity assessment
        is_valid = risk_score < 30  # Valid if risk score is low

        # Add risk level interpretation
        if risk_score >= 70:
            risk_flags.insert(0, "🔴 HIGH RISK - Major SSL issues detected")
        elif risk_score >= 40:
            risk_flags.insert(0, "🟡 MEDIUM RISK - SSL concerns present")
        elif risk_score >= 20:
            risk_flags.insert(0, "🟢 LOW RISK - Minor SSL issues")
        else:
            risk_flags.insert(0, "🟢 VERY LOW RISK - SSL appears secure")

        return is_valid, details

    except ssl.SSLError as e:
        error_msg = f"SSL Error: {str(e)}"
        return False, {"error": error_msg, "risk_score": 60, "risk_flags": [f"SSL connection failed: {error_msg}"]}
    except socket.gaierror as e:
        error_msg = f"DNS Error: {str(e)}"
        return False, {"error": error_msg, "risk_score": 50, "risk_flags": [f"DNS resolution failed: {error_msg}"]}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return False, {"error": error_msg, "risk_score": 40, "risk_flags": [f"SSL analysis failed: {error_msg}"]}
