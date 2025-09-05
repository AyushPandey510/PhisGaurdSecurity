import os
import requests
import re
from typing import Tuple, List
from virustotal_python import Virustotal

# Load configuration from environment variables
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 10))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", 10))

def check_url(url: str) -> Tuple[int, List[str]]:
    """
    Check URL risk using:
    1. Enhanced Heuristics
    2. Google Safe Browsing
    Returns (risk_score, details)
    """
    risk = 0
    details = []

    # Enhanced Heuristic checks
    # Suspicious patterns
    if re.search(r"--", url):
        risk += 15
        details.append("Suspicious: too many hyphens")

    # Suspicious TLDs
    suspicious_tlds = [".xyz", ".top", ".click", ".zip", ".club", ".online", ".site", ".space", ".website", ".tech"]
    if any(url.endswith(tld) for tld in suspicious_tlds):
        risk += 20
        details.append("Suspicious TLD")

    # IP address in URL
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url):
        risk += 25
        details.append("IP address in URL (suspicious)")

    # Too many subdomains
    domain_parts = url.split('.')
    if len(domain_parts) > 3:
        risk += 10
        details.append("Too many subdomains")

    # Common phishing keywords
    phishing_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'banking', 'paypal', 'ebay', 'amazon']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        risk += 15
        details.append("Contains common phishing keywords")

    # Shortened URLs
    shortened_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    if any(short_domain in url for short_domain in shortened_domains):
        risk += 20
        details.append("Shortened URL (cannot verify destination)")

    # Non-HTTPS
    if not url.startswith('https://'):
        risk += 10
        details.append("Not using HTTPS")

    # Google Safe Browsing (only if API key is set and valid)
    if GOOGLE_SAFE_BROWSING_API_KEY and GOOGLE_SAFE_BROWSING_API_KEY != "your-google-safe-browsing-api-key-here":
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            r = requests.post(gsb_url, json=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                response_data = r.json()
                if response_data.get("matches"):
                    risk += 50
                    details.append("🚨 FLAGGED BY GOOGLE SAFE BROWSING")
                else:
                    details.append("✅ URL not flagged by Google Safe Browsing")
            else:
                # Log more detailed error information
                error_details = f"GSB API error {r.status_code}"
                try:
                    error_response = r.json()
                    if "error" in error_response:
                        error_details += f": {error_response['error'].get('message', 'Unknown error')}"
                except:
                    error_details += f": {r.text[:200]}"  # First 200 chars of response
                details.append(error_details)
        except Exception as e:
            details.append(f"GSB check failed: {str(e)}")
    else:
        details.append("⚠️ Google Safe Browsing not configured (add API key to .env)")

    # VirusTotal URL Analysis (primary threat intelligence source)
    if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "your-virustotal-api-key-here":
        try:
            # Initialize VirusTotal client
            vt = Virustotal(API_KEY=VIRUSTOTAL_API_KEY)

            # Get URL analysis - use the correct method for URL ID
            try:
                # Try different methods to get URL ID
                if hasattr(vt, 'get_url_id'):
                    url_id = vt.get_url_id(url)
                elif hasattr(vt, 'get_id'):
                    url_id = vt.get_id(url)
                else:
                    # Fallback: create URL ID manually
                    import base64
                    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

                resp = vt.request(f"urls/{url_id}")
            except Exception as method_error:
                # If URL ID methods fail, try to submit URL for analysis
                try:
                    submit_resp = vt.request("urls", data={"url": url}, method="POST")
                    if submit_resp.status_code == 200:
                        submit_data = submit_resp.json()
                        if "data" in submit_data:
                            url_id = submit_data["data"]["id"]
                            resp = vt.request(f"urls/{url_id}")
                        else:
                            raise Exception("No data in submission response")
                    else:
                        raise Exception(f"Submission failed: {submit_resp.status_code}")
                except Exception as submit_error:
                    raise Exception(f"Both URL ID generation and submission failed: {str(method_error)}, {str(submit_error)}")

            if resp.status_code == 200:
                vt_data = resp.json().get("data", {})
                attributes = vt_data.get("attributes", {})

                # Get analysis stats
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious = last_analysis_stats.get("malicious", 0)
                suspicious = last_analysis_stats.get("suspicious", 0)
                harmless = last_analysis_stats.get("harmless", 0)
                undetected = last_analysis_stats.get("undetected", 0)

                total_scans = malicious + suspicious + harmless + undetected

                if total_scans > 0:
                    malicious_percentage = (malicious / total_scans) * 100

                    if malicious > 0:
                        risk += min(malicious_percentage * 2, 60)  # Up to 60 points for malicious detections
                        details.append(f"🚨 VIRUSTOTAL: {malicious}/{total_scans} engines detected as malicious")

                    if suspicious > 0:
                        risk += min(suspicious * 5, 20)  # Up to 20 points for suspicious
                        details.append(f"⚠️ VIRUSTOTAL: {suspicious}/{total_scans} engines flagged as suspicious")

                    if malicious == 0 and suspicious == 0:
                        details.append(f"✅ VIRUSTOTAL: {harmless}/{total_scans} engines reported clean")
                    else:
                        details.append(f"📊 VIRUSTOTAL: Analyzed by {total_scans} engines")
                else:
                    details.append("ℹ️ VIRUSTOTAL: URL not yet analyzed")

            elif resp.status_code == 404:
                # URL not found in VirusTotal, submit for analysis
                try:
                    submit_resp = vt.request("urls", data={"url": url}, method="POST")
                    if submit_resp.status_code == 200:
                        details.append("📤 VIRUSTOTAL: URL submitted for analysis")
                    else:
                        details.append("⚠️ VIRUSTOTAL: Could not submit URL for analysis")
                except Exception as submit_error:
                    details.append(f"⚠️ VIRUSTOTAL: Submission failed - {str(submit_error)}")

            else:
                error_msg = f"VirusTotal API error {resp.status_code}"
                try:
                    error_data = resp.json()
                    if "error" in error_data:
                        error_msg += f": {error_data['error'].get('message', 'Unknown error')}"
                except:
                    pass
                details.append(f"⚠️ {error_msg}")

        except Exception as e:
            details.append(f"⚠️ VirusTotal check failed: {str(e)}")
    else:
        details.append("⚠️ VirusTotal not configured (add API key to .env)")

    # Additional heuristic checks for better detection
    # Check for suspicious URL patterns
    if re.search(r'\d{4,}', url):  # Long numbers (potentially credit card numbers)
        risk += 15
        details.append("Contains long numeric sequences")

    if 'javascript:' in url.lower():
        risk += 30
        details.append("Contains JavaScript execution")

    if len(url) > 200:  # Very long URLs
        risk += 10
        details.append("Unusually long URL")

    # Ensure minimum risk for obviously suspicious sites
    final_risk = min(risk, 100)

    # Add risk level interpretation
    if final_risk >= 70:
        details.insert(0, "🔴 HIGH RISK - Exercise extreme caution!")
    elif final_risk >= 40:
        details.insert(0, "🟡 MEDIUM RISK - Proceed with caution")
    elif final_risk >= 20:
        details.insert(0, "🟢 LOW RISK - Generally safe")
    else:
        details.insert(0, "🟢 VERY LOW RISK - Appears safe")

    return final_risk, details
