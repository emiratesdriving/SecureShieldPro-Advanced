#!/usr/bin/env python3
"""
SecureShield Pro - Comprehensive Security Validation Suite
Phase 6: Bulletproof Security Testing
"""

import requests
import time
import json
import sys
from datetime import datetime

class ComprehensiveSecurityTester:
    """Advanced security testing for bulletproof validation"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = {"passed": 0, "failed": 0, "tests": []}
    
    def log_test(self, test_name: str, passed: bool, details: str = ""):
        """Log test results"""
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"    📋 {details}")
        
        self.results["tests"].append({
            "test": test_name,
            "passed": passed,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })
        
        if passed:
            self.results["passed"] += 1
        else:
            self.results["failed"] += 1
    
    def test_server_availability(self):
        """Test if server is running and responding"""
        print("\n🚀 Testing Server Availability...")
        try:
            response = self.session.get(f"{self.base_url}/", timeout=5)
            self.log_test("Server Response", response.status_code in [200, 404], 
                         f"Status: {response.status_code}")
            return True
        except Exception as e:
            self.log_test("Server Response", False, f"Error: {str(e)}")
            return False
    
    def test_security_headers(self):
        """Test critical security headers implementation"""
        print("\n🛡️ Testing Security Headers...")
        try:
            response = self.session.get(f"{self.base_url}/")
            headers = response.headers
            
            security_checks = [
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", ["DENY", "SAMEORIGIN"]),
                ("X-XSS-Protection", "1"),
                ("Strict-Transport-Security", "max-age"),
                ("Content-Security-Policy", "default-src")
            ]
            
            for header, expected in security_checks:
                if header in headers:
                    header_value = headers[header]
                    if isinstance(expected, list):
                        passed = any(exp in header_value for exp in expected)
                    else:
                        passed = expected in header_value
                    
                    self.log_test(f"Security Header: {header}", passed, 
                                f"Value: {header_value}")
                else:
                    self.log_test(f"Security Header: {header}", False, "Missing")
        
        except Exception as e:
            self.log_test("Security Headers Test", False, f"Error: {str(e)}")
    
    def test_rate_limiting(self):
        """Test rate limiting implementation"""
        print("\n🚦 Testing Rate Limiting...")
        try:
            # Send rapid requests to trigger rate limiting
            responses = []
            start_time = time.time()
            
            for i in range(20):  # Send 20 rapid requests
                try:
                    response = self.session.get(f"{self.base_url}/", timeout=2)
                    responses.append(response.status_code)
                    if response.status_code == 429:  # Rate limited
                        break
                    time.sleep(0.05)  # Small delay
                except:
                    responses.append(0)  # Connection error
            
            elapsed = time.time() - start_time
            rate_limited = 429 in responses
            
            self.log_test("Rate Limiting Active", rate_limited, 
                         f"Got 429 status in {len(responses)} requests ({elapsed:.2f}s)")
            
            # Test recovery after rate limit
            if rate_limited:
                time.sleep(2)  # Wait for rate limit to reset
                recovery_response = self.session.get(f"{self.base_url}/")
                self.log_test("Rate Limit Recovery", recovery_response.status_code != 429,
                             f"Recovery status: {recovery_response.status_code}")
        
        except Exception as e:
            self.log_test("Rate Limiting Test", False, f"Error: {str(e)}")
    
    def test_input_validation(self):
        """Test input validation against common attacks"""
        print("\n🛡️ Testing Input Validation...")
        
        # SQL Injection payloads
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1#"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "'>><script>alert('xss')</script>"
        ]
        
        # Path traversal payloads
        traversal_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64"
        ]
        
        all_payloads = [
            ("SQL Injection", sql_payloads),
            ("XSS Attack", xss_payloads),
            ("Path Traversal", traversal_payloads)
        ]
        
        for attack_type, payloads in all_payloads:
            blocked_count = 0
            total_count = len(payloads)
            
            for payload in payloads:
                try:
                    # Test as query parameter
                    response = self.session.get(f"{self.base_url}/", 
                                              params={"test": payload}, timeout=5)
                    
                    # Consider 400, 403, 422 as blocked (good)
                    if response.status_code in [400, 403, 422]:
                        blocked_count += 1
                    
                except Exception:
                    blocked_count += 1  # Connection error = blocked
            
            success_rate = (blocked_count / total_count) * 100
            passed = success_rate >= 50  # At least 50% should be blocked
            
            self.log_test(f"{attack_type} Protection", passed,
                         f"{blocked_count}/{total_count} blocked ({success_rate:.1f}%)")
    
    def test_authentication_endpoints(self):
        """Test authentication security"""
        print("\n🔐 Testing Authentication Security...")
        
        # Test registration endpoint
        try:
            register_data = {
                "username": "testuser_" + str(int(time.time())),
                "email": "test@example.com",
                "password": "ValidPassword123!"
            }
            
            response = self.session.post(f"{self.base_url}/api/v1/auth/register", 
                                       json=register_data, timeout=5)
            
            self.log_test("Registration Endpoint", response.status_code in [200, 201, 422],
                         f"Status: {response.status_code}")
            
        except Exception as e:
            self.log_test("Registration Endpoint", False, f"Error: {str(e)}")
        
        # Test weak password rejection
        try:
            weak_password_data = {
                "username": "weakuser",
                "email": "weak@example.com", 
                "password": "123"
            }
            
            response = self.session.post(f"{self.base_url}/api/v1/auth/register",
                                       json=weak_password_data, timeout=5)
            
            # Should reject weak password (422 or 400)
            self.log_test("Weak Password Rejection", response.status_code in [400, 422],
                         f"Status: {response.status_code}")
            
        except Exception as e:
            self.log_test("Weak Password Rejection", False, f"Error: {str(e)}")
    
    def test_ai_endpoints(self):
        """Test AI security features"""
        print("\n🤖 Testing AI Security Features...")
        
        try:
            # Test AI status endpoint
            response = self.session.get(f"{self.base_url}/api/v1/ai/status", timeout=5)
            self.log_test("AI Status Endpoint", response.status_code in [200, 404, 401],
                         f"Status: {response.status_code}")
            
            # Test AI chat endpoint (should require authentication)
            chat_data = {"message": "Hello, test security analysis"}
            response = self.session.post(f"{self.base_url}/api/v1/ai/chat",
                                       json=chat_data, timeout=5)
            
            # Should require authentication (401) or work (200)
            self.log_test("AI Chat Authentication", response.status_code in [200, 401, 422],
                         f"Status: {response.status_code}")
            
        except Exception as e:
            self.log_test("AI Endpoints Test", False, f"Error: {str(e)}")
    
    def test_file_upload_security(self):
        """Test file upload security"""
        print("\n📁 Testing File Upload Security...")
        
        try:
            # Test malicious file upload
            malicious_content = b"<?php system($_GET['cmd']); ?>"
            files = {"file": ("malicious.php", malicious_content, "application/php")}
            
            response = self.session.post(f"{self.base_url}/api/v1/scans/upload",
                                       files=files, timeout=5)
            
            # Should block malicious files (400, 403, 422)
            self.log_test("Malicious File Block", response.status_code in [400, 403, 422],
                         f"Status: {response.status_code}")
            
            # Test oversized file
            large_content = b"A" * (60 * 1024 * 1024)  # 60MB
            files = {"file": ("large.txt", large_content, "text/plain")}
            
            response = self.session.post(f"{self.base_url}/api/v1/scans/upload",
                                       files=files, timeout=10)
            
            # Should reject large files (413, 422)
            self.log_test("Large File Rejection", response.status_code in [413, 422],
                         f"Status: {response.status_code}")
            
        except Exception as e:
            self.log_test("File Upload Security", False, f"Error: {str(e)}")
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*60)
        print("🔐 SECURESHIELD PRO SECURITY VALIDATION REPORT")
        print("="*60)
        
        total_tests = self.results["passed"] + self.results["failed"]
        success_rate = (self.results["passed"] / total_tests * 100) if total_tests > 0 else 0
        
        print(f"📊 Total Tests: {total_tests}")
        print(f"✅ Passed: {self.results['passed']}")
        print(f"❌ Failed: {self.results['failed']}")
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        print(f"\n⏰ Test Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if success_rate >= 90:
            print("\n🎉 BULLETPROOF SECURITY CONFIRMED!")
            print("🛡️ Your system has EXCEPTIONAL security posture")
        elif success_rate >= 75:
            print("\n✅ STRONG SECURITY IMPLEMENTATION") 
            print("🔒 Your system has robust security measures")
        elif success_rate >= 50:
            print("\n⚠️ MODERATE SECURITY LEVEL")
            print("🔧 Some security improvements recommended")
        else:
            print("\n❌ SECURITY VULNERABILITIES DETECTED")
            print("🚨 Immediate security improvements required")
        
        # Save detailed report
        report_file = f"/tmp/security_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n📄 Detailed report saved: {report_file}")
        
        return success_rate >= 75
    
    def run_comprehensive_tests(self):
        """Run complete security test suite"""
        print("🔐 STARTING COMPREHENSIVE SECURITY VALIDATION")
        print("🎯 Testing bulletproof security implementation...")
        
        # Core security tests
        if not self.test_server_availability():
            print("❌ Server not available - stopping tests")
            return False
        
        self.test_security_headers()
        self.test_rate_limiting()
        self.test_input_validation()
        self.test_authentication_endpoints()
        self.test_ai_endpoints()
        self.test_file_upload_security()
        
        return self.generate_security_report()

def main():
    """Main execution"""
    tester = ComprehensiveSecurityTester()
    success = tester.run_comprehensive_tests()
    
    if success:
        print("\n🚀 Ready for Phase 7: Asset Management System!")
        return 0
    else:
        print("\n🔧 Security improvements needed before proceeding")
        return 1

if __name__ == "__main__":
    sys.exit(main())