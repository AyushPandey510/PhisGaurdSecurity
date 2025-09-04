#!/usr/bin/env python3
"""
Quick test script to verify the PhisGuard backend is working correctly.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_environment_variables():
    """Test that environment variables are loaded correctly."""
    print("🔧 Testing Environment Variables...")

    required_vars = [
        'FLASK_DEBUG',
        'SECRET_KEY',
        'HOST',
        'PORT',
        'REQUEST_TIMEOUT',
        'MAX_REDIRECTS'
    ]

    for var in required_vars:
        value = os.getenv(var)
        if value:
            print(f"  ✅ {var}: {value}")
        else:
            print(f"  ❌ {var}: Not set")

def test_imports():
    """Test that all modules can be imported."""
    print("\n📦 Testing Module Imports...")

    try:
        from services.url_checker import check_url
        print("  ✅ URL Checker imported successfully")

        from services.ssl_checker import check_ssl
        print("  ✅ SSL Checker imported successfully")

        from services.link_expander import expand_link
        print("  ✅ Link Expander imported successfully")

        from services.breach_checker import check_password_breach
        print("  ✅ Breach Checker imported successfully")

        from utils.risk_scorer import RiskScorer
        print("  ✅ Risk Scorer imported successfully")

        from app import app
        print("  ✅ Main Flask app imported successfully")

    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False

    return True

def test_basic_functionality():
    """Test basic functionality of services."""
    print("\n🧪 Testing Basic Functionality...")

    try:
        # Test URL checker with a safe URL
        from services.url_checker import check_url
        risk_score, details = check_url("https://www.google.com")
        print(f"  ✅ URL Check: Risk score {risk_score}/100 for google.com")

        # Test SSL checker
        from services.ssl_checker import check_ssl
        is_valid, ssl_details = check_ssl("https://www.google.com")
        print(f"  ✅ SSL Check: Certificate {'valid' if is_valid else 'invalid'} for google.com")

        # Test link expander
        from services.link_expander import expand_link
        final_url, redirect_chain, analysis, error = expand_link("https://www.google.com")
        print(f"  ✅ Link Expansion: {'No redirects' if not redirect_chain else f'{len(redirect_chain)} redirects'} for google.com")

        # Test password breach checker
        from services.breach_checker import check_password_breach
        breached, count = check_password_breach("testpassword123")
        print(f"  ✅ Password Check: {'Compromised' if breached else 'Safe'} (found in {count} breaches)")

        # Test risk scorer
        from utils.risk_scorer import quick_risk_assessment
        assessment = quick_risk_assessment(url="https://www.google.com")
        print(f"  ✅ Risk Assessment: {assessment['risk_level']} risk level")

    except Exception as e:
        print(f"  ❌ Functionality test error: {e}")
        return False

    return True

def main():
    """Run all tests."""
    print("🚀 PhisGuard Backend - Comprehensive Test Suite")
    print("=" * 50)

    # Test environment variables
    test_environment_variables()

    # Test imports
    imports_ok = test_imports()

    if imports_ok:
        # Test functionality
        functionality_ok = test_basic_functionality()

        if functionality_ok:
            print("\n🎉 All tests passed! PhisGuard backend is ready to use.")
            print("\n📋 Next steps:")
            print("  1. Set your API keys in .env file:")
            print("     - GOOGLE_SAFE_BROWSING_API_KEY")
            print("     - PHISHTANK_API_KEY")
            print("     - HIBP_API_KEY")
            print("  2. Run the application: python3 app.py")
            print("  3. Test the API endpoints at http://localhost:5000")
        else:
            print("\n❌ Some functionality tests failed.")
    else:
        print("\n❌ Import tests failed. Check dependencies.")

if __name__ == "__main__":
    main()