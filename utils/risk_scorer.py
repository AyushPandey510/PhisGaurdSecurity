from typing import Dict, List, Any, Tuple

class RiskScorer:
    def __init__(self):
        self.weights = {
            'url_risk': 0.4,
            'ssl_validity': 0.2,
            'link_redirects': 0.15,
            'domain_reputation': 0.15,
            'breach_history': 0.1
        }

    def calculate_overall_risk(self, url_results: Dict = None, ssl_results: Dict = None,
                              link_results: Dict = None, breach_results: Dict = None) -> Dict[str, Any]:
        """
        Calculate overall risk score based on all security checks.
        Returns comprehensive risk assessment.
        """
        risk_components = {}
        total_score = 0
        max_possible_score = 100

        # URL Risk Assessment
        if url_results:
            url_score = url_results.get('risk_score', 0)
            risk_components['url_risk'] = {
                'score': url_score,
                'weight': self.weights['url_risk'],
                'details': url_results.get('details', []),
                'recommendation': url_results.get('recommendation', 'unknown')
            }
            total_score += url_score * self.weights['url_risk']

        # SSL Risk Assessment - Use enhanced SSL risk scoring
        if ssl_results:
            # Use the risk_score from enhanced SSL checker if available
            ssl_risk_score = ssl_results.get('risk_score', 0)
            ssl_details = ssl_results.get('risk_flags', [])

            # If no enhanced risk score, fall back to basic assessment
            if ssl_risk_score == 0:
                if ssl_results.get('connection_type') == 'http':
                    ssl_risk_score = 60  # HTTP connection risk
                    ssl_details.append("Connection is unencrypted (HTTP)")
                elif ssl_results.get('is_valid') is False:
                    ssl_risk_score = 80  # High risk for invalid SSL
                    ssl_details.append("SSL certificate is invalid")
                elif ssl_results.get('is_expired'):
                    ssl_risk_score = 60  # Medium-high risk for expired SSL
                    ssl_details.append("SSL certificate is expired")
                elif ssl_results.get('days_until_expiry', 30) < 30:
                    ssl_risk_score = 40  # Medium risk for expiring soon
                    ssl_details.append(f"SSL certificate expires in {ssl_results.get('days_until_expiry')} days")
                elif ssl_results.get('is_self_signed'):
                    ssl_risk_score = 50  # High risk for self-signed
                    ssl_details.append("Self-signed certificate detected")
                elif ssl_results.get('is_wildcard'):
                    ssl_risk_score = 15  # Low-medium risk for wildcard
                    ssl_details.append("Wildcard certificate - verify subdomain trust")
                else:
                    ssl_risk_score = 10  # Low risk for valid SSL
                    ssl_details.append("SSL certificate is valid")

            risk_components['ssl_risk'] = {
                'score': ssl_risk_score,
                'weight': self.weights['ssl_validity'],
                'details': ssl_details
            }
            total_score += ssl_risk_score * self.weights['ssl_validity']

        # Link Expansion Risk Assessment
        if link_results:
            redirect_score = 0
            redirect_details = []

            redirect_chain = link_results.get('redirect_chain', [])
            final_url = link_results.get('final_url')

            if len(redirect_chain) > 3:
                redirect_score = 30  # Medium risk for many redirects
                redirect_details.append(f"Multiple redirects detected ({len(redirect_chain)})")
            elif len(redirect_chain) > 0:
                redirect_score = 15  # Low-medium risk for some redirects
                redirect_details.append(f"Redirects detected ({len(redirect_chain)})")

            # Check for suspicious redirect patterns
            if redirect_chain:
                suspicious_redirects = 0
                for redirect in redirect_chain:
                    redirect_url = redirect.get('redirect_to', '')
                    if any(domain in redirect_url.lower() for domain in ['bit.ly', 'tinyurl', 'goo.gl']):
                        suspicious_redirects += 1

                if suspicious_redirects > 0:
                    redirect_score += 20
                    redirect_details.append("Redirects through URL shorteners detected")

            risk_components['redirect_risk'] = {
                'score': redirect_score,
                'weight': self.weights['link_redirects'],
                'details': redirect_details
            }
            total_score += redirect_score * self.weights['link_redirects']

        # Breach Risk Assessment
        if breach_results:
            breach_score = 0
            breach_details = []

            if breach_results.get('password_breach_check'):
                if breach_results['password_breach_check'].get('breached'):
                    breach_score = 50
                    count = breach_results['password_breach_check'].get('breach_count', 0)
                    breach_details.append(f"Password found in {count} breaches")

            if breach_results.get('email_check'):
                if breach_results['email_check'].get('breached'):
                    breach_score = max(breach_score, 40)
                    count = breach_results['email_check'].get('breach_count', 0)
                    breach_details.append(f"Email found in {count} breaches")

            risk_components['breach_risk'] = {
                'score': breach_score,
                'weight': self.weights['breach_history'],
                'details': breach_details
            }
            total_score += breach_score * self.weights['breach_history']

        # Domain Reputation (placeholder - would need external API)
        domain_score = 0  # Placeholder
        risk_components['domain_reputation'] = {
            'score': domain_score,
            'weight': self.weights['domain_reputation'],
            'details': ["Domain reputation check not implemented"]
        }
        total_score += domain_score * self.weights['domain_reputation']

        # Calculate final risk level
        final_score = min(100, max(0, total_score))

        risk_level = self._get_risk_level(final_score)
        recommendations = self._get_recommendations(final_score, risk_components)

        return {
            'overall_score': round(final_score, 1),
            'risk_level': risk_level,
            'components': risk_components,
            'recommendations': recommendations,
            'assessment_timestamp': self._get_timestamp()
        }

    def _get_risk_level(self, score: float) -> str:
        """Convert numerical score to risk level."""
        if score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "very_low"

    def _get_recommendations(self, score: float, components: Dict) -> List[str]:
        """Generate actionable recommendations based on risk assessment."""
        recommendations = []

        if score >= 70:
            recommendations.append("🚨 HIGH RISK: Do not proceed. This appears to be malicious.")
            recommendations.append("Report this URL to security authorities if appropriate.")
        elif score >= 40:
            recommendations.append("⚠️ MEDIUM RISK: Exercise caution when interacting with this resource.")
            recommendations.append("Verify the destination manually before proceeding.")
        elif score >= 20:
            recommendations.append("ℹ️ LOW RISK: Generally safe, but monitor for suspicious activity.")
        else:
            recommendations.append("✅ VERY LOW RISK: This resource appears safe to use.")

        # Component-specific recommendations
        if 'ssl_risk' in components and components['ssl_risk']['score'] >= 60:
            recommendations.append("SSL issues detected - connection may not be secure.")

        if 'breach_risk' in components and components['breach_risk']['score'] >= 40:
            recommendations.append("Credentials have been compromised - change passwords immediately.")

        if 'redirect_risk' in components and components['redirect_risk']['score'] >= 30:
            recommendations.append("Multiple redirects detected - verify final destination.")

        return recommendations

    def _get_timestamp(self) -> str:
        """Get current timestamp for assessment."""
        from datetime import datetime
        return datetime.utcnow().isoformat()

def quick_risk_assessment(url: str = None, email: str = None, password: str = None) -> Dict[str, Any]:
    """
    Quick risk assessment for basic inputs.
    This is a simplified version for when you don't have full analysis results.
    """
    scorer = RiskScorer()
    score = 0
    factors = []

    if url:
        # Basic URL heuristics
        if 'http://' in url:
            score += 10
            factors.append("Uses HTTP instead of HTTPS")

        suspicious_patterns = ['login', 'password', 'bank', 'paypal', 'secure']
        if any(pattern in url.lower() for pattern in suspicious_patterns):
            score += 15
            factors.append("Contains sensitive keywords")

        if '--' in url:
            score += 20
            factors.append("Suspicious hyphens in domain")

    if email:
        # Basic email check
        if '@' not in email or '.' not in email.split('@')[1]:
            score += 30
            factors.append("Invalid email format")

    if password:
        # Basic password strength
        if len(password) < 8:
            score += 25
            factors.append("Weak password length")

        if not any(c.isupper() for c in password):
            score += 15
            factors.append("Missing uppercase letters")

    risk_level = scorer._get_risk_level(score)

    return {
        'quick_score': min(100, score),
        'risk_level': risk_level,
        'factors': factors,
        'recommendations': scorer._get_recommendations(score, {})
    }
