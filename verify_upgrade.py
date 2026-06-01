"""
verify_research_level.py - Verification Script for Advanced Cyber Defense
Tests the integrated research-level features:
1. Bayesian Probabilistic Decisions
2. Cross-IP Behavioral Correlation
3. Polymorphic Pattern Generalization (Evolution)
"""

import requests
import time
import json
import random

BASE_URL = "http://127.0.0.1:5000"

def test_bayesian_fusion():
    print("\n[TEST] 1. Bayesian Decision Fusion")
    ip = f"172.16.0.{random.randint(1,254)}"
    # Simulate an attack that might skip simple heuristics but should be caught by fused evidence
    # High frequency + some failures + suspicious user agent
    print(f"  Sending burst of requests from {ip}...")
    for i in range(15):
        try:
            r = requests.get(f"{BASE_URL}/", headers={
                "X-Forwarded-For": ip,
                "User-Agent": "Mozilla/5.0 (compatible; ResearchBot/1.0; +http://example.com)"
            })
            p_attack = r.headers.get("X-Risk-Score", "unknown") # We might need to expose P(attack) if different
            print(f"    Request {i+1}: Status {r.status_code}, Risk {p_attack}")
            if r.status_code == 403:
                print(f"  [SUCCESS] Bayesian Engine blocked the request.")
                break
        except Exception as e:
            print(f"    Error: {e}")
            break
        time.sleep(0.1)

def test_cross_ip_correlation():
    print("\n[TEST] 2. Cross-IP Behavioral Correlation")
    ip1 = "10.10.10.1"
    ip2 = "10.10.10.2"
    
    pattern = ["/api/status", "/api/health", "/api/data", "/login"]
    
    print(f"  Simulating identical behavior from {ip1} and {ip2}...")
    for ep in pattern:
        for ip in [ip1, ip2]:
            try:
                r = requests.get(f"{BASE_URL}{ep}", headers={"X-Forwarded-For": ip})
                print(f"    {ip} -> {ep}: {r.status_code}")
            except Exception as e:
                print(f"    Error: {e}")
        time.sleep(0.5)
    
    print("  Checking if correlation score is elevated...")
    # This would be visible in the system logs (log_system_event) or dashboard

def test_evolution_generalization():
    print("\n[TEST] 3. Polymorphic Pattern Generalization (Evolution)")
    ip = f"192.168.10.{random.randint(1,254)}"
    
    # Send a cluster of "unknown" but structurally similar payloads to the honeypot
    print(f"  Injecting structurally similar payloads to honeypot from {ip}...")
    payloads = [
        "<?php echo 'attack_ABC_123'; ?>",
        "<?php echo 'attack_XYZ_456'; ?>",
        "<?php echo 'attack_DEF_789'; ?>",
        "<?php echo 'attack_GHI_000'; ?>",
    ]
    
    for i, p in enumerate(payloads):
        try:
            # Hit a honeypot endpoint with the payload
            r = requests.post(f"{BASE_URL}/debug", data=p, headers={
                "X-Forwarded-For": ip,
                "Content-Type": "text/plain"
            })
            print(f"    Payload {i+1} sent to /debug: {r.status_code}")
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(0.5)
    
    print("  Waiting for EvolutionController to generalize and inject a rule...")
    time.sleep(2)
    # The result should be a new rule in the database with "PolyGen" in the name

if __name__ == "__main__":
    print("-" * 50)
    print("  RESEARCH-LEVEL CYBER DEFENSE VERIFICATION")
    print("-" * 50)
    
    try:
        # Check if server is up
        r = requests.get(BASE_URL, timeout=2)
        print(f"Server is UP (Status: {r.status_code})")
        
        test_bayesian_fusion()
        test_cross_ip_correlation()
        test_evolution_generalization()
        
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Could not connect to {BASE_URL}. Is the server running?")
        print("Run 'python app.py' in a separate terminal first.")
    
    print("\nVerification sequence complete.")
