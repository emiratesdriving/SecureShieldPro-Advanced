#!/usr/bin/env python3
"""
SecureShield Pro Security Testing Suite
Comprehensive security validation following OWASP guidelines
"""

import requests
import asyncio
import aiohttp
import json
import time
import subprocess
import sys
from typing import Dict, List, Any
from urllib.parse import urljoin
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityTester:
    """Comprehensive security testing suite"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
    
    def run_all_tests(self):
        """Run complete security test suite"""
        logger.info("Starting SecureShield Pro Security Test Suite")
        
        # Test categories
        test_categories = [
            ("Authentication Security", self.test_authentication_security),
            ("Input Validation", self.test_input_validation),
            ("Security Headers", self.test_security_headers),
            ("Rate Limiting", self.test_rate_limiting),
            ("CORS Configuration", self.test_cors_configuration),
            ("File Upload Security", self.test_file_upload_security),
            ("SQL Injection Protection", self.test_sql_injection_protection),
            ("XSS Protection", self.test_xss_protection),
            ("CSRF Protection", self.test_csrf_protection),
            ("Information Disclosure", self.test_information_disclosure),
        ]
        
        for category, test_func in test_categories:
            logger.info(f"Running {category} tests...")
            try:
                results = test_func()
                self.test_results.extend(results)
            except Exception as e:
                logger.error(f"Error in {category} tests: {e}")
                self.test_results.append({
                    "category": category,
                    "test": "General",
                    "status": "ERROR",
                    "message": str(e)
                })
        
        # Generate report
        self.generate_report()
    
    def test_authentication_security(self) -> List[Dict[str, Any]]:
        """Test authentication security measures"""
        results = []
        
        # Test 1: Password strength requirements
        weak_passwords = ["123456", "password", "admin", "test"]
        for password in weak_passwords:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/api/v1/auth/register"),
                    json={
                        "username": f"test_{int(time.time())}",
                        "email": f"test_{int(time.time())}@example.com",
                        "password": password
                    }
                )
                if response.status_code == 400:
                    results.append({
                        "category": "Authentication",
                        "test": f"Weak Password Rejection ({password})",
                        "status": "PASS",
                        "message": "Weak password properly rejected"
                    })
                else:
                    results.append({
                        "category": "Authentication",
                        "test": f"Weak Password Rejection ({password})",
                        "status": "FAIL",
                        "message": f"Weak password accepted: {password}"
                    })
            except Exception as e:
                results.append({
                    "category": "Authentication",
                    "test": f"Weak Password Test ({password})",
                    "status": "ERROR",
                    "message": str(e)
                })
        
        # Test 2: Account lockout mechanism
        try:
            # Attempt multiple failed logins
            for i in range(6):  # Exceed the limit
                response = self.session.post(
                    urljoin(self.base_url, "/api/v1/auth/login"),
                    json={
                        "username": "nonexistent_user",
                        "password": "wrong_password"
                    }
                )
            
            # Check if account is locked
            if response.status_code == 429 or "locked" in response.text.lower():
                results.append({
                    "category": "Authentication",
                    "test": "Account Lockout",
                    "status": "PASS",
                    "message": "Account lockout mechanism working"
                })
            else:
                results.append({
                    "category": "Authentication",
                    "test": "Account Lockout",
                    "status": "FAIL",
                    "message": "No account lockout after multiple failed attempts"
                })
        except Exception as e:
            results.append({
                "category": "Authentication",
                "test": "Account Lockout",
                "status": "ERROR",
                "message": str(e)
            })
        
        return results
    
    def test_input_validation(self) -> List[Dict[str, Any]]:
        """Test input validation and sanitization"""
        results = []
        
        # Malicious payloads
        payloads = [
            ("SQL Injection", "'; DROP TABLE users; --"),
            ("XSS", "<script>alert('xss')</script>"),
            ("Command Injection", "; cat /etc/passwd"),
            ("Path Traversal", "../../../etc/passwd"),
            ("XXE", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"),
        ]
        
        for attack_type, payload in payloads:
            try:
                # Test various endpoints
                endpoints = [
                    "/api/v1/auth/register",
                    "/api/v1/scans/upload",
                ]
                
                for endpoint in endpoints:
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        json={"malicious_input": payload}
                    )
                    
                    if response.status_code == 400 and "invalid" in response.text.lower():
                        results.append({
                            "category": "Input Validation",
                            "test": f"{attack_type} on {endpoint}",
                            "status": "PASS",
                            "message": "Malicious input properly rejected"
                        })
                    else:
                        results.append({
                            "category": "Input Validation",
                            "test": f"{attack_type} on {endpoint}",
                            "status": "FAIL",
                            "message": f"Malicious input not properly filtered: {payload[:50]}"
                        })
            except Exception as e:
                results.append({
                    "category": "Input Validation",
                    "test": f"{attack_type}",
                    "status": "ERROR",
                    "message": str(e)
                })
        
        return results
    
    def test_security_headers(self) -> List[Dict[str, Any]]:
        """Test security headers implementation"""
        results = []
        
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Referrer-Policy"
        ]
        
        try:
            response = self.session.get(urljoin(self.base_url, "/health"))
            
            for header in required_headers:
                if header in response.headers:
                    results.append({
                        "category": "Security Headers",
                        "test": f"{header} Present",
                        "status": "PASS",
                        "message": f"Header present: {response.headers[header]}"
                    })
                else:
                    results.append({
                        "category": "Security Headers",
                        "test": f"{header} Present",
                        "status": "FAIL",
                        "message": f"Required security header missing: {header}"
                    })
            
            # Check for information disclosure in Server header
            server_header = response.headers.get("Server", "")
            if "SecureShield-Pro" in server_header:
                results.append({
                    "category": "Security Headers",
                    "test": "Server Header",
                    "status": "PASS",
                    "message": "Server header properly masked"
                })
            else:
                results.append({
                    "category": "Security Headers",
                    "test": "Server Header",
                    "status": "WARN",
                    "message": f"Server header reveals information: {server_header}"
                })
        
        except Exception as e:
            results.append({
                "category": "Security Headers",
                "test": "General",
                "status": "ERROR",
                "message": str(e)
            })
        
        return results
    
    def test_rate_limiting(self) -> List[Dict[str, Any]]:
        """Test rate limiting implementation"""
        results = []
        
        try:
            # Rapid requests to test rate limiting
            responses = []
            for i in range(150):  # Exceed rate limit
                response = self.session.get(urljoin(self.base_url, "/health"))
                responses.append(response.status_code)
                if i % 50 == 0:
                    time.sleep(0.1)  # Small delay
            
            # Check if any requests were rate limited
            rate_limited = any(status == 429 for status in responses)
            
            if rate_limited:
                results.append({
                    "category": "Rate Limiting",
                    "test": "Rate Limit Enforcement",
                    "status": "PASS",
                    "message": "Rate limiting is working"
                })
            else:
                results.append({
                    "category": "Rate Limiting",
                    "test": "Rate Limit Enforcement",
                    "status": "FAIL",
                    "message": "No rate limiting detected after 150 requests"
                })
        
        except Exception as e:
            results.append({
                "category": "Rate Limiting",
                "test": "Rate Limit Test",
                "status": "ERROR",
                "message": str(e)
            })
        
        return results
    
    def test_cors_configuration(self) -> List[Dict[str, Any]]:
        """Test CORS configuration security"""
        results = []
        
        try:
            # Test with malicious origin
            headers = {"Origin": "https://malicious-site.com"}
            response = self.session.options(
                urljoin(self.base_url, "/api/v1/health"),
                headers=headers
            )
            
            cors_origin = response.headers.get("Access-Control-Allow-Origin", "")
            
            if cors_origin != "*" and "malicious-site.com" not in cors_origin:
                results.append({
                    "category": "CORS",
                    "test": "Origin Validation",
                    "status": "PASS",
                    "message": "CORS properly configured"
                })
            else:
                results.append({
                    "category": "CORS",
                    "test": "Origin Validation",
                    "status": "FAIL",
                    "message": f"Unsafe CORS configuration: {cors_origin}"
                })
        
        except Exception as e:
            results.append({
                "category": "CORS",
                "test": "CORS Configuration",
                "status": "ERROR",
                "message": str(e)
            })
        
        return results
    
    def test_file_upload_security(self) -> List[Dict[str, Any]]:
        """Test file upload security measures"""
        results = []
        
        # Malicious file types
        malicious_files = [
            ("executable.exe", b"MZ\x90\x00"),  # PE executable
            ("script.sh", b"#!/bin/bash\nrm -rf /"),  # Shell script
            ("malware.bat", b"@echo off\ndir C:\\"),  # Batch file
        ]
        
        for filename, content in malicious_files:
            try:
                files = {"file": (filename, content)}
                response = self.session.post(
                    urljoin(self.base_url, "/api/v1/scans/upload"),
                    files=files
                )
                
                if response.status_code == 400:
                    results.append({
                        "category": "File Upload",
                        "test": f"Malicious File Rejection ({filename})",
                        "status": "PASS",
                        "message": "Malicious file properly rejected"
                    })
                else:
                    results.append({
                        "category": "File Upload",
                        "test": f"Malicious File Rejection ({filename})",
                        "status": "FAIL",
                        "message": f"Malicious file accepted: {filename}"
                    })
            except Exception as e:
                results.append({
                    "category": "File Upload",
                    "test": f"File Upload ({filename})",
                    "status": "ERROR",
                    "message": str(e)
                })
        
        return results
    
    def test_sql_injection_protection(self) -> List[Dict[str, Any]]:
        """Test SQL injection protection"""
        results = []
        
        sql_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users;--",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "1' OR 1=1#"
        ]
        
        for payload in sql_payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/api/v1/auth/login"),
                    json={
                        "username": payload,
                        "password": "any"
                    }
                )
                
                # Should be rejected or return 401, not 500 (SQL error)
                if response.status_code in [400, 401] and response.status_code != 500:
                    results.append({
                        "category": "SQL Injection",
                        "test": f"SQL Payload ({payload[:20]}...)",
                        "status": "PASS",
                        "message": "SQL injection payload properly handled"
                    })
                else:
                    results.append({
                        "category": "SQL Injection",
                        "test": f"SQL Payload ({payload[:20]}...)",
                        "status": "FAIL",
                        "message": f"Unexpected response to SQL payload: {response.status_code}"
                    })
            except Exception as e:
                results.append({
                    "category": "SQL Injection",
                    "test": f"SQL Test ({payload[:20]}...)",
                    "status": "ERROR",
                    "message": str(e)
                })
        
        return results
    
    def test_xss_protection(self) -> List[Dict[str, Any]]:
        """Test XSS protection measures"""
        results = []
        
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/api/v1/auth/register"),
                    json={
                        "username": payload,
                        "email": "test@example.com",
                        "password": "ValidPassword123!"
                    }
                )
                
                if response.status_code == 400:
                    results.append({
                        "category": "XSS Protection",
                        "test": f"XSS Payload ({payload[:20]}...)",
                        "status": "PASS",
                        "message": "XSS payload properly rejected"
                    })
                else:
                    results.append({
                        "category": "XSS Protection",
                        "test": f"XSS Payload ({payload[:20]}...)",
                        "status": "FAIL",
                        "message": f"XSS payload not properly filtered"
                    })
            except Exception as e:
                results.append({
                    "category": "XSS Protection",
                    "test": f"XSS Test ({payload[:20]}...)",
                    "status": "ERROR",
                    "message": str(e)
                })
        
        return results
    
    def test_csrf_protection(self) -> List[Dict[str, Any]]:
        """Test CSRF protection measures"""
        results = []
        
        try:
            # Attempt state-changing operation without proper authentication
            response = self.session.post(
                urljoin(self.base_url, "/api/v1/scans/start"),
                json={"file_id": "123"}
            )
            
            if response.status_code == 401:
                results.append({
                    "category": "CSRF Protection",
                    "test": "Unauthenticated State Change",
                    "status": "PASS",
                    "message": "Unauthenticated requests properly rejected"
                })
            else:
                results.append({
                    "category": "CSRF Protection",
                    "test": "Unauthenticated State Change",
                    "status": "FAIL",
                    "message": f"Unauthenticated request accepted: {response.status_code}"
                })
        except Exception as e:
            results.append({
                "category": "CSRF Protection",
                "test": "CSRF Test",
                "status": "ERROR",
                "message": str(e)
            })
        
        return results
    
    def test_information_disclosure(self) -> List[Dict[str, Any]]:
        """Test for information disclosure vulnerabilities"""
        results = []
        
        # Test endpoints that might reveal information
        test_endpoints = [
            "/admin",
            "/api/v1/debug",
            "/api/v1/config",
            "/.env",
            "/backup",
            "/database",
        ]
        
        for endpoint in test_endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                
                if response.status_code == 404:
                    results.append({
                        "category": "Information Disclosure",
                        "test": f"Sensitive Endpoint ({endpoint})",
                        "status": "PASS",
                        "message": "Sensitive endpoint properly protected"
                    })
                elif response.status_code == 200:
                    results.append({
                        "category": "Information Disclosure",
                        "test": f"Sensitive Endpoint ({endpoint})",
                        "status": "FAIL",
                        "message": f"Sensitive endpoint accessible: {endpoint}"
                    })
            except Exception as e:
                results.append({
                    "category": "Information Disclosure",
                    "test": f"Endpoint Test ({endpoint})",
                    "status": "ERROR",
                    "message": str(e)
                })
        
        return results
    
    def generate_report(self):
        """Generate comprehensive security test report"""
        logger.info("Generating Security Test Report")
        
        # Count results by status
        pass_count = sum(1 for r in self.test_results if r["status"] == "PASS")
        fail_count = sum(1 for r in self.test_results if r["status"] == "FAIL")
        error_count = sum(1 for r in self.test_results if r["status"] == "ERROR")
        warn_count = sum(1 for r in self.test_results if r["status"] == "WARN")
        total_count = len(self.test_results)
        
        # Calculate security score
        score = (pass_count / total_count) * 100 if total_count > 0 else 0
        
        print("\n" + "="*80)
        print("SecureShield Pro Security Test Report")
        print("="*80)
        print(f"Total Tests: {total_count}")
        print(f"✅ Passed: {pass_count}")
        print(f"❌ Failed: {fail_count}")
        print(f"⚠️  Warnings: {warn_count}")
        print(f"💥 Errors: {error_count}")
        print(f"Security Score: {score:.1f}%")
        print("="*80)
        
        # Group by category
        categories = {}
        for result in self.test_results:
            category = result["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(result)
        
        # Print detailed results
        for category, tests in categories.items():
            print(f"\n{category}:")
            print("-" * len(category))
            
            for test in tests:
                status_icon = {
                    "PASS": "✅",
                    "FAIL": "❌",
                    "WARN": "⚠️",
                    "ERROR": "💥"
                }.get(test["status"], "?")
                
                print(f"  {status_icon} {test['test']}: {test['message']}")
        
        # Security recommendations
        if fail_count > 0 or error_count > 0:
            print("\n" + "="*80)
            print("🔧 Security Recommendations:")
            print("="*80)
            
            failed_categories = set(r["category"] for r in self.test_results if r["status"] in ["FAIL", "ERROR"])
            
            recommendations = {
                "Authentication": "Review password policies and account lockout mechanisms",
                "Input Validation": "Implement comprehensive input sanitization",
                "Security Headers": "Configure all required security headers",
                "Rate Limiting": "Implement proper rate limiting on all endpoints",
                "CORS": "Configure CORS with specific allowed origins",
                "File Upload": "Implement file type validation and content scanning",
                "SQL Injection": "Use parameterized queries and input validation",
                "XSS Protection": "Implement output encoding and CSP headers",
                "CSRF Protection": "Implement CSRF tokens for state-changing operations",
                "Information Disclosure": "Remove or protect sensitive endpoints"
            }
            
            for category in failed_categories:
                if category in recommendations:
                    print(f"• {category}: {recommendations[category]}")
        
        print("\n" + "="*80)
        
        # Save detailed report to file
        with open("security_test_report.json", "w") as f:
            json.dump({
                "summary": {
                    "total": total_count,
                    "passed": pass_count,
                    "failed": fail_count,
                    "warnings": warn_count,
                    "errors": error_count,
                    "score": score
                },
                "results": self.test_results
            }, f, indent=2)
        
        logger.info("Detailed report saved to security_test_report.json")


if __name__ == "__main__":
    # Check if server is running
    tester = SecurityTester()
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        logger.info("Server is running, starting security tests...")
        tester.run_all_tests()
    except requests.exceptions.RequestException:
        logger.error("Server is not running. Please start the backend server first.")
        sys.exit(1)