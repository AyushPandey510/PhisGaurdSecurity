#!/usr/bin/env python3
"""
Debug script to test breach data loading and lookup
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.breach_checker import load_breach_data, check_email_breach, email_breaches

def test_breach_lookup():
    print("Testing breach data loading and lookup...")

    # Load breach data
    load_breach_data()

    # Check if user162@test.com exists
    test_email = 'user162@test.com'
    print(f"Looking up email: {test_email}")

    if test_email in email_breaches:
        print(f"✅ Found {len(email_breaches[test_email])} breach(es) for {test_email}")
        for breach in email_breaches[test_email]:
            print(f"  - Breach name: {breach['breach_name']}")
    else:
        print(f"❌ Email {test_email} not found in breach data")
        print(f"Total emails in breach data: {len(email_breaches)}")

        # Show some sample emails
        sample_emails = list(email_breaches.keys())[:5]
        print(f"Sample emails in breach data: {sample_emails}")

    # Test the check_email_breach function
    result = check_email_breach(test_email)
    print(f"check_email_breach result: {result}")

if __name__ == "__main__":
    test_breach_lookup()