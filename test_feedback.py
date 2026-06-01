import requests
import json

URL = "http://localhost:5000/api/defense/feedback"

def test_feedback(ip, is_attack):
    payload = {"ip": ip, "is_attack": is_attack}
    try:
        response = requests.post(URL, json=payload)
        print(f"Feedback for {ip} (is_attack={is_attack}): {response.status_code}")
        print(response.json())
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Test cases (assuming these IPs have some recent activity)
    # test_feedback("192.168.1.100", True)
    # test_feedback("10.0.0.5", False)
    print("Feedback test script ready. Run while app is active.")
