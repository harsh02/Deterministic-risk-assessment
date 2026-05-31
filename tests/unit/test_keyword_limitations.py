#!/usr/bin/env python3
"""Show where keyword matching fails"""

test_cases = [
    {
        "description": "Attacker modified database configurations allowing unauthorized data access",
        "expected": "High impact (data manipulation)",
        "keyword_result": "❌ Misses - no keyword match for 'modified configurations'",
    },
    {
        "description": "Vulnerability allows threat actor to gain elevated privileges",
        "expected": "High impact (privilege escalation)",
        "keyword_result": "❌ Misses - no 'privilege escalation' keyword",
    },
    {
        "description": "Flaw enables remote adversary to execute malicious payloads",
        "expected": "Critical impact (RCE)",
        "keyword_result": "❌ Might miss - uses 'execute malicious payloads' not 'code execution'",
    },
    {
        "description": "Data breach was successfully prevented by security controls",
        "expected": "Low impact (prevented)",
        "keyword_result": "❌ False positive - triggers 'data breach' keyword",
    },
    {
        "description": "Customer payment information including card numbers compromised",
        "expected": "Critical sensitivity (payment data)",
        "keyword_result": "✅ Works - has 'payment' and 'card' keywords",
    },
]

print("KEYWORD MATCHING LIMITATIONS\n")
for i, test in enumerate(test_cases, 1):
    print(f"{i}. {test['description'][:60]}...")
    print(f"   Expected: {test['expected']}")
    print(f"   Keyword: {test['keyword_result']}\n")
