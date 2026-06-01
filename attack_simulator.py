"""
attack_simulator.py - Attack Simulation Module
Simulates brute force, flooding, scanning, and injection attacks.
"""

import requests, time, random, string, threading, json


BASE_URL = "http://127.0.0.1:8000"
FAKE_IPS = [f"10.0.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(10)]


def simulate_normal_user(duration=30):
    """Simulate normal browsing behavior."""
    print("\n[NORMAL USER] Starting normal browsing simulation...")
    endpoints = ["/", "/api/status", "/api/health", "/login"]
    ip = f"192.168.1.{random.randint(10,50)}"
    start = time.time()
    count = 0
    while time.time() - start < duration:
        ep = random.choice(endpoints)
        try:
            r = requests.get(f"{BASE_URL}{ep}", headers={"X-Forwarded-For": ip,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}, timeout=5)
            count += 1
            print(f"  [NORMAL] {ep} -> {r.status_code}")
        except Exception as e:
            print(f"  [ERROR] {e}")
        time.sleep(random.uniform(2, 5))
    print(f"[NORMAL USER] Done. {count} requests sent.")


def simulate_brute_force(target="/login", attempts=25):
    """Simulate brute force login attack."""
    print(f"\n[BRUTE FORCE] Starting {attempts} login attempts...")
    ip = random.choice(FAKE_IPS)
    success = 0
    for i in range(attempts):
        user = random.choice(["admin", "root", "administrator", "test"])
        pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        try:
            r = requests.post(f"{BASE_URL}{target}",
                json={"username": user, "password": pwd},
                headers={"X-Forwarded-For": ip, "User-Agent": "Mozilla/5.0"}, timeout=5)
            status = "BLOCKED" if r.status_code == 403 else str(r.status_code)
            print(f"  [{i+1}/{attempts}] {user}:{pwd[:4]}*** -> {status}")
            if r.status_code == 403:
                print(f"  [!] Attack detected and blocked after {i+1} attempts!")
                break
            success += 1
        except Exception as e:
            print(f"  [ERROR] {e}")
        time.sleep(random.uniform(0.1, 0.5))
    print(f"[BRUTE FORCE] Done from {ip}. {success} requests went through.")


def simulate_request_flood(duration=15, threads=3):
    """Simulate rapid request flooding (DDoS-style)."""
    print(f"\n[FLOOD] Starting {threads}-thread flood for {duration}s...")
    ip = random.choice(FAKE_IPS)
    counter = {"total": 0, "blocked": 0}

    def flood_worker():
        endpoints = ["/", "/api/status", "/api/health", "/login", "/api/data"]
        start = time.time()
        while time.time() - start < duration:
            ep = random.choice(endpoints)
            try:
                r = requests.get(f"{BASE_URL}{ep}",
                    headers={"X-Forwarded-For": ip, "User-Agent": "python-flood/1.0"}, timeout=3)
                counter["total"] += 1
                if r.status_code == 403:
                    counter["blocked"] += 1
            except:
                pass
            time.sleep(random.uniform(0.01, 0.1))

    workers = [threading.Thread(target=flood_worker) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    print(f"[FLOOD] Done from {ip}. Total={counter['total']}, Blocked={counter['blocked']}")


def simulate_endpoint_scan():
    """Simulate endpoint scanning/enumeration."""
    print("\n[SCANNER] Starting endpoint scan...")
    ip = random.choice(FAKE_IPS)
    targets = [
        "/admin", "/api/config", "/api/keys", "/api/users", "/api/database",
        "/.env", "/debug", "/api/secrets", "/wp-admin", "/wp-login.php",
        "/api/users/1", "/api/users/2", "/api/users/3", "/api/users/4",
        "/api/users/5", "/api/users/6", "/api/users/7",
        "/backup", "/phpmyadmin", "/api/v1/internal", "/graphql",
    ]
    results = {"accessible": 0, "blocked": 0, "not_found": 0}
    for ep in targets:
        try:
            r = requests.get(f"{BASE_URL}{ep}",
                headers={"X-Forwarded-For": ip, "User-Agent": "Nikto/2.1.6"}, timeout=5)
            if r.status_code == 403:
                results["blocked"] += 1
                label = "BLOCKED"
            elif r.status_code == 404:
                results["not_found"] += 1
                label = "NOT FOUND"
            else:
                results["accessible"] += 1
                label = f"FOUND ({r.status_code})"
            print(f"  {ep:30s} -> {label}")
        except Exception as e:
            print(f"  {ep:30s} -> ERROR: {e}")
        time.sleep(random.uniform(0.1, 0.3))
    print(f"[SCANNER] Done from {ip}. {results}")


def simulate_sql_injection():
    """Simulate SQL injection attacks."""
    print("\n[SQL INJECTION] Starting injection attempts...")
    ip = random.choice(FAKE_IPS)
    payloads = [
        "' OR 1=1 --", "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "admin'--", "1; DELETE FROM sessions WHERE 1=1",
        "' OR ''='", "1' AND 1=1 UNION SELECT NULL,NULL--",
    ]
    for i, payload in enumerate(payloads):
        try:
            r = requests.post(f"{BASE_URL}/login",
                json={"username": payload, "password": "test"},
                headers={"X-Forwarded-For": ip}, timeout=5)
            status = "BLOCKED" if r.status_code == 403 else str(r.status_code)
            print(f"  [{i+1}] Payload: {payload[:40]:40s} -> {status}")
        except Exception as e:
            print(f"  [{i+1}] ERROR: {e}")
        time.sleep(0.3)
    print(f"[SQL INJECTION] Done from {ip}.")


def simulate_xss_attack():
    """Simulate XSS attacks."""
    print("\n[XSS] Starting XSS attempts...")
    ip = random.choice(FAKE_IPS)
    payloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(document.cookie)',
        '<svg onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
    ]
    for i, payload in enumerate(payloads):
        try:
            r = requests.post(f"{BASE_URL}/api/data",
                json={"input": payload},
                headers={"X-Forwarded-For": ip}, timeout=5)
            status = "BLOCKED" if r.status_code == 403 else str(r.status_code)
            print(f"  [{i+1}] {payload[:40]:40s} -> {status}")
        except Exception as e:
            print(f"  [{i+1}] ERROR: {e}")
        time.sleep(0.3)
    print(f"[XSS] Done from {ip}.")


def run_full_demo():
    """Run all attack simulations in sequence."""
    print("=" * 60)
    print("  AUTONOMOUS CYBER DEFENSE - ATTACK SIMULATION DEMO")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")
    print("Starting simulations...\n")

    # Phase 1: Normal traffic baseline
    simulate_normal_user(duration=10)
    time.sleep(2)

    # Phase 2: Brute force attack
    simulate_brute_force(attempts=20)
    time.sleep(2)

    # Phase 3: Request flooding
    simulate_request_flood(duration=10, threads=3)
    time.sleep(2)

    # Phase 4: Endpoint scanning
    simulate_endpoint_scan()
    time.sleep(2)

    # Phase 5: SQL Injection
    simulate_sql_injection()
    time.sleep(2)

    # Phase 6: XSS
    simulate_xss_attack()

    print("\n" + "=" * 60)
    print("  ALL SIMULATIONS COMPLETE")
    print("  Check the dashboard at http://127.0.0.1:5000/dashboard")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        sims = {
            "normal": lambda: simulate_normal_user(30),
            "brute": lambda: simulate_brute_force(attempts=20),
            "flood": lambda: simulate_request_flood(15, 3),
            "scan": simulate_endpoint_scan,
            "sqli": simulate_sql_injection,
            "xss": simulate_xss_attack,
            "all": run_full_demo,
        }
        if cmd in sims:
            sims[cmd]()
        else:
            print(f"Unknown: {cmd}. Use: {list(sims.keys())}")
    else:
        run_full_demo()
