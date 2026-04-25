#!/usr/bin/env python3
"""
Simple Security Vulnerability Scanner
Inspired by Snyk - scans Python code for common security issues.
"""

import re
import os
import sys

# ------------------------------------------------------------------
# Sample vulnerable code (as per experiment Step 6)
SAMPLE_CODE = '''import os
import subprocess

user_input = input("Enter a command to run: ")
os.system(user_input)

USERNAME = "admin"
PASSWORD = "12345"

subprocess.call("ls -la", shell=True)
'''
# ------------------------------------------------------------------

def scan_hardcoded_secrets(code: str):
    """Find hardcoded credentials, API keys, tokens."""
    findings = []
    patterns = {
        "Password": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
        "Username": r"(?i)(username|user|login)\s*=\s*['\"][^'\"]+['\"]",
        "API Key": r"(?i)(api_key|apikey|token|secret)\s*=\s*['\"][^'\"]+['\"]"
    }
    for name, pattern in patterns.items():
        matches = re.finditer(pattern, code)
        for match in matches:
            findings.append({
                "type": "Hardcoded Credential",
                "subtype": name,
                "line": code.count('\n', 0, match.start()) + 1,
                "snippet": match.group().strip()
            })
    return findings

def scan_insecure_functions(code: str):
    """Detect dangerous function calls."""
    dangerous = [
        ("os.system", "Command injection risk (os.system)"),
        ("subprocess.call", "Shell injection risk if shell=True"),
        ("eval", "Code injection risk"),
        ("exec", "Code injection risk"),
        ("__import__", "Dynamic import risk"),
        ("pickle.loads", "Deserialization vulnerability")
    ]
    findings = []
    for func, description in dangerous:
        pattern = rf"\b{re.escape(func)}\s*\("
        matches = re.finditer(pattern, code)
        for match in matches:
            findings.append({
                "type": "Insecure Function",
                "function": func,
                "description": description,
                "line": code.count('\n', 0, match.start()) + 1
            })
    return findings

def scan_shell_true(code: str):
    """Find subprocess calls with shell=True."""
    findings = []
    pattern = r"subprocess\.call\s*\([^)]*shell\s*=\s*True"
    matches = re.finditer(pattern, code)
    for match in matches:
        findings.append({
            "type": "Dangerous Shell Usage",
            "detail": "subprocess.call(..., shell=True) allows command injection",
            "line": code.count('\n', 0, match.start()) + 1,
            "snippet": match.group()
        })
    return findings

def scan_weak_encryption(code: str):
    """Look for weak cryptographic algorithms."""
    weak = ["md5", "sha1", "des", "rc4"]
    findings = []
    for algo in weak:
        pattern = rf"\b{re.escape(algo)}\s*\("
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            findings.append({
                "type": "Weak Cryptography",
                "algorithm": algo.upper(),
                "line": code.count('\n', 0, match.start()) + 1,
                "recommendation": f"Use a strong algorithm like SHA-256 or AES instead of {algo}"
            })
    return findings

def scan_input_validation(code: str):
    """Check for missing input validation/sanitization patterns."""
    findings = []
    # Look for input() used without validation
    input_pattern = r"input\s*\([^)]*\)"
    matches = re.finditer(input_pattern, code)
    for match in matches:
        findings.append({
            "type": "Missing Input Validation",
            "detail": "Direct use of input() without validation or sanitization",
            "line": code.count('\n', 0, match.start()) + 1,
            "suggestion": "Validate and sanitize user input to prevent injection"
        })
    return findings

def main():
    print("=" * 70)
    print("🔒 SECURITY VULNERABILITY SCAN (Snyk-style)")
    print("=" * 70)
    print("\n📄 Scanning: sample_code.py\n")

    # Load sample code
    code = SAMPLE_CODE

    # Run all scans
    all_findings = []
    all_findings.extend(scan_hardcoded_secrets(code))
    all_findings.extend(scan_insecure_functions(code))
    all_findings.extend(scan_shell_true(code))
    all_findings.extend(scan_weak_encryption(code))
    all_findings.extend(scan_input_validation(code))

    if not all_findings:
        print("✅ No obvious security issues found.")
        return 0

    # Display results
    print(f"⚠️  Found {len(all_findings)} potential security issues:\n")
    for i, issue in enumerate(all_findings, 1):
        print(f"[{i}] {issue.get('type', 'Issue')}")
        if 'subtype' in issue:
            print(f"    └─ {issue['subtype']}")
        if 'function' in issue:
            print(f"    └─ Function: {issue['function']}")
        if 'description' in issue:
            print(f"    └─ Risk: {issue['description']}")
        if 'detail' in issue:
            print(f"    └─ Detail: {issue['detail']}")
        if 'algorithm' in issue:
            print(f"    └─ Weak Algo: {issue['algorithm']}")
        if 'line' in issue:
            print(f"    └─ Line: {issue['line']}")
        if 'snippet' in issue:
            print(f"    └─ Snippet: {issue['snippet'][:60]}")
        if 'suggestion' in issue or 'recommendation' in issue:
            sugg = issue.get('suggestion') or issue.get('recommendation')
            print(f"    └─ Suggestion: {sugg}")
        print()

    # Summary by severity (simple heuristic)
    critical = [i for i in all_findings if "injection" in str(i).lower()]
    high = [i for i in all_findings if "hardcoded" in str(i).lower() or "shell" in str(i).lower()]
    
    print("-" * 70)
    print("📊 SUMMARY")
    print(f"   Total issues: {len(all_findings)}")
    print(f"   🔴 Critical (injection risks): {len(critical)}")
    print(f"   🟠 High (hardcoded secrets / shell): {len(high)}")
    print("-" * 70)
    print("\n💡 Recommendation: Fix critical issues first, then high risks.")
    print("   - Never use os.system() or shell=True with user input.")
    print("   - Never hardcode credentials.")
    print("   - Always validate/sanitize user input.\n")

    return 0

if __name__ == "__main__":
    sys.exit(main())