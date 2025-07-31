from email import message_from_file
import re
import requests
from dotenv import load_dotenv
import os

load_dotenv()
ABUSEIPDB_API_KEY= os.getenv("ABUSEIPDB_API_KEY")

def load_email_headers(path):
    with open(path, 'r') as file:
        msg = message_from_file(file)
    return msg

def display_basic_headers(msg):
    print("From:", msg.get("From"))
    print("To:", msg.get("To"))
    print("Subject:", msg.get("Subject"))
    print("Date:", msg.get("Date"))
    print("Return-Path:", msg.get("Return-Path"))
    print("Received headers:")
    
    received_headers = msg.get_all("Received")
    if received_headers:
        for i, received in enumerate(received_headers, 1):
            print(f"  {i}: {received}")
    else:
        print("  None found")

def analyze_threat_indicators(msg):
    print("\n[+] Threat Indicators")

    from_addr = msg.get("From")
    return_path = msg.get("Return-Path")
    reply_to = msg.get("Reply-To")

    # 1. Mismatch check: From vs Return-Path
    if return_path and from_addr and return_path not in from_addr:
        print(f"  ⚠️ Mismatch between 'From' and 'Return-Path': {from_addr} vs {return_path}")
    
    # 2. Suspicious Reply-To
    if reply_to and reply_to not in from_addr:
        print(f"  ⚠️ 'Reply-To' is different from 'From': {reply_to} vs {from_addr}")

    # 3. SPF/DKIM/DMARC checks
    auth_results = msg.get("Authentication-Results")
    received_spf = msg.get("Received-SPF")

    if auth_results:
        print("  Authentication-Results:")
        results = auth_results.lower().split(";")
        for result in results:
            if any(proto in result for proto in ["spf=", "dkim=", "dmarc="]):
                verdict = result.strip().split()[0]  # grab only `dkim=pass`, etc.
                print(f"    🔍 {verdict}")
                if "fail" in verdict or "softfail" in verdict:
                    print("      ⚠️ Possible spoofing or misconfigured authentication")
        else:
            print("  ⚠️ No Authentication-Results header found")

    if received_spf:
        print("  Received-SPF:", received_spf.strip())
        if "fail" in received_spf.lower() or "softfail" in received_spf.lower():
            print("    ⚠️ SPF failure or softfail")

def extract_ip_addresses(headers):
    received_headers = headers.get_all('Received', [])
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ip_addresses = []

    for header in received_headers:
        matches = ip_pattern.findall(header)
        for ip in matches:
            octets = ip.split('.')
            # Filter: all 4 parts must be 0-255, no leading zeroes (except '0' itself)
            if len(octets) == 4 and all(
                octet.isdigit() and
                0 <= int(octet) <= 255 and
                (octet == "0" or not octet.startswith("0"))
                for octet in octets
            ):
                ip_addresses.append(ip)

    return ip_addresses

def check_ip_reputation(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)
        data = response.json()["data"]
        abuse_score = data["abuseConfidenceScore"]
        total_reports = data["totalReports"]
        country = data["countryCode"]

        return {
            "ip": ip,
            "abuse_score": abuse_score,
            "total_reports": total_reports,
            "country": country
        }

    except Exception as e:
        print(f"[!] Error checking IP {ip}: {e}")
        return None


if __name__ == "__main__":
    email_path = "samples/samples.txt"
    msg = load_email_headers(email_path)
    display_basic_headers(msg)
    analyze_threat_indicators(msg)
    ip_addresses = extract_ip_addresses(msg)
    print("\nExtracted IP Addresses from Received Headers:")
    for ip in ip_addresses:
        print(f"- {ip}")
    ips = extract_ip_addresses(msg)
    for ip in ips:
        result = check_ip_reputation(ip)
        if result:
            print(f"IP: {result['ip']} ({result['country']})")
            print(f"  > Abuse Score: {result['abuse_score']}/100")
            print(f"  > Total Reports: {result['total_reports']}")

