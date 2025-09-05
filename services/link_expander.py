import requests
from urllib.parse import urlparse
import os

# Load configuration from environment variables
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 10))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", 10))

def expand_link(url: str, max_redirects: int = None):
    if max_redirects is None:
        max_redirects = MAX_REDIRECTS
    """
    Expand a shortened URL by following redirects with enhanced analysis.
    Returns (final_url, redirect_chain, analysis, error)
    """
    try:
        # Validate URL format
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None, [], {}, "Invalid URL format"

        original_domain = parsed.netloc.lower()

        try:
            with requests.Session() as session:
                session.max_redirects = max_redirects
                response = session.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT)

            # Build redirect chain from history
            redirect_chain = []
            for r in response.history:
                redirect_chain.append({
                    'url': r.url,
                    'status_code': r.status_code,
                    'redirect_to': r.headers.get('Location', '')
                })

            final_url = response.url

        except requests.exceptions.ConnectionError as e:
            return url, [], {}, f"Connection failed: Unable to reach {url}"
        except requests.exceptions.Timeout as e:
            return url, [], {}, f"Timeout: {url} took too long to respond"
        except requests.exceptions.TooManyRedirects as e:
            return url, [], {}, f"Too many redirects: {url} has excessive redirect chain"
        except requests.exceptions.RequestException as e:
            return url, [], {}, f"Request failed: {str(e)}"

        # Enhanced analysis
        analysis = analyze_redirect_chain(url, final_url, redirect_chain, original_domain)

        return final_url, redirect_chain, analysis, None

    except Exception as e:
        return None, [], {}, f"Unexpected error: {str(e)}"


def analyze_redirect_chain(original_url: str, final_url: str, redirect_chain: list, original_domain: str):
    """
    Analyze the redirect chain for security risks and format display data.
    """
    analysis = {
        'visual_chain': [],
        'risk_flags': [],
        'suspicious': False,
        'risk_score': 0
    }

    # Build visual redirect chain
    current_url = original_url
    analysis['visual_chain'].append(current_url)

    for redirect in redirect_chain:
        analysis['visual_chain'].append(f"→ {redirect['redirect_to']}")
        current_url = redirect['redirect_to']

    # Analyze final URL domain
    final_parsed = urlparse(final_url)
    final_domain = final_parsed.netloc.lower()

    # Check for domain mismatch (big difference)
    if original_domain != final_domain:
        # Extract main domain parts
        orig_parts = original_domain.split('.')
        final_parts = final_domain.split('.')

        # Remove common prefixes/suffixes for comparison
        orig_main = '.'.join(orig_parts[-2:]) if len(orig_parts) >= 2 else original_domain
        final_main = '.'.join(final_parts[-2:]) if len(final_parts) >= 2 else final_domain

        if orig_main != final_main:
            analysis['risk_flags'].append("⚠️ Domain mismatch - final domain differs significantly from original")
            analysis['risk_score'] += 15
            analysis['suspicious'] = True

    # Check for too many redirects (>3)
    if len(redirect_chain) > 3:
        analysis['risk_flags'].append(f"🚨 Too many redirects ({len(redirect_chain)} hops) - suspicious activity")
        analysis['risk_score'] += 20
        analysis['suspicious'] = True

    # Check for redirect loops
    urls_seen = set()
    for redirect in redirect_chain:
        url_key = redirect['url'].lower()
        if url_key in urls_seen:
            analysis['risk_flags'].append("🔄 Redirect loop detected - suspicious")
            analysis['risk_score'] += 25
            analysis['suspicious'] = True
            break
        urls_seen.add(url_key)

    # Check for suspicious redirect patterns
    for redirect in redirect_chain:
        redirect_url = redirect['redirect_to'].lower()
        if any(suspicious in redirect_url for suspicious in ['javascript:', 'data:', 'vbscript:']):
            analysis['risk_flags'].append("🚨 Malicious redirect pattern detected")
            analysis['risk_score'] += 30
            analysis['suspicious'] = True

    # Format visual chain as single string
    analysis['formatted_chain'] = ' '.join(analysis['visual_chain'])

    return analysis

def is_shortened_url(url: str):
    """
    Check if URL is from a known URL shortener service.
    """
    shortener_domains = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'tiny.cc', 'cli.gs', 'su.pr', 'wp.me',
        'post.ly', 'snipurl.com', 'snurl.com', 'snip.ly', 'tr.im',
        'fb.me', 'lnkd.in', 'db.tt', 'qr.ae', '1url.com', 'tweez.me',
        'v.gd', 'bc.vc', 'u.to', 'j.mp', 'buzurl.com', 'cur.lv',
        'yourls.org', 'x.co', 'prettylinkpro.com', 'scrnch.me',
        'filoops.info', 'vzturl.com', 'qr.net', '1link.in',
        'sharein.com', 'easyurl.net', 'tu.pw', 'cut.by'
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]

        return domain in shortener_domains
    except:
        return False
