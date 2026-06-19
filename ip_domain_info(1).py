#!/usr/bin/env python3
"""
IP / Domain Information Finder
--------------------------------
Ye program kisi IP address ya domain (jaise google.com) ke baare me
poori jaankari deta hai:

  1) IP Info (geolocation, ISP/owner, hosting provider, ASN)
  2) Domain WHOIS Info (agar domain diya ho) - registrar, creation
     date (start time), expiry date, name servers, abuse contact email
  3) SSL Certificate Info - certificate kisne issue kiya aur kab tak valid hai
  4) Webpage Info - status code, title, server software, aur webpage
     par publicly listed social media/contact links

Requirements (pehle install karein):
    pip install requests python-whois

Run karne ka tarika:
    python ip_domain_info.py
"""

import socket
import ssl
import re
import sys
from datetime import datetime

try:
    import requests
except ImportError:
    print("Error: 'requests' library install nahi hai.")
    print("Install karein: pip install requests")
    sys.exit(1)

try:
    import whois
except ImportError:
    whois = None  # WHOIS optional rahega, IP info phir bhi chalega


def is_ip_address(value: str) -> bool:
    """Check karta hai ki diya gaya input IP address hai ya domain."""
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def resolve_domain_to_ip(domain: str) -> str | None:
    """Domain ko uske IP address me convert karta hai."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_ip_info(ip: str) -> dict:
    """
    Free API (ip-api.com) se IP ki jaankari leta hai:
    location, ISP/owner, organization, ASN (hosting provider ka pata)
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "Unknown error")}
        return data
    except requests.RequestException as e:
        return {"error": str(e)}


def get_domain_whois(domain: str) -> dict:
    """
    Domain ki WHOIS jaankari leta hai:
    - Registrar (kis company se domain register hua)
    - Creation date (start time)
    - Expiration date (expiry time)
    - Name servers (web page kis server (hosting) se judi hai)
    """
    if whois is None:
        return {"error": "'python-whois' library install nahi hai. Install karein: pip install python-whois"}

    try:
        w = whois.whois(domain)

        # Abuse contact dhoondhna - kayi baar ye 'emails' list me hota hai
        # ya 'whois_server' raw text me "abuse" keyword ke paas milta hai
        abuse_email = None
        emails = w.emails
        if emails:
            email_list = [emails] if isinstance(emails, str) else emails
            for e in email_list:
                if "abuse" in e.lower():
                    abuse_email = e
                    break
            if abuse_email is None and email_list:
                abuse_email = email_list[0]  # koi specific abuse email na mile to pehla email de do

        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,      # start time
            "expiration_date": w.expiration_date,  # expiry time
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,        # server jahan website hosted/managed hai
            "emails": w.emails,
            "abuse_email": abuse_email,
            "org": w.org,
            "country": w.country,
        }
    except Exception as e:
        return {"error": str(e)}


def get_ssl_info(domain: str) -> dict:
    """
    Webpage ke SSL certificate ki jaankari nikalta hai:
    - Kis company/CA (Certificate Authority) ne certificate issue kiya
    - Certificate kab se valid hai aur kab expire hoga
    - Certificate kis domain ke liye issue hua hai
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        # Date format ko readable banana
        fmt = "%b %d %H:%M:%S %Y %Z"
        valid_from = datetime.strptime(not_before, fmt) if not_before else None
        valid_until = datetime.strptime(not_after, fmt) if not_after else None

        return {
            "issued_to": subject.get("commonName"),
            "issued_by": issuer.get("organizationName") or issuer.get("commonName"),
            "valid_from": valid_from,
            "valid_until": valid_until,
        }
    except Exception as e:
        return {"error": str(e)}


def get_social_links(html: str) -> list:
    """
    Webpage ke HTML me se social media aur contact links dhoondta hai
    (jaise Facebook, Instagram, Twitter/X, LinkedIn, YouTube, mailto, tel)
    """
    patterns = {
        "Facebook": r"https?://(?:www\.)?facebook\.com/[^\s\"'<>]+",
        "Instagram": r"https?://(?:www\.)?instagram\.com/[^\s\"'<>]+",
        "Twitter/X": r"https?://(?:www\.)?(?:twitter|x)\.com/[^\s\"'<>]+",
        "LinkedIn": r"https?://(?:www\.)?linkedin\.com/[^\s\"'<>]+",
        "YouTube": r"https?://(?:www\.)?youtube\.com/[^\s\"'<>]+",
        "WhatsApp": r"https?://(?:wa\.me|api\.whatsapp\.com)/[^\s\"'<>]+",
        "Telegram": r"https?://(?:t\.me)/[^\s\"'<>]+",
        "Email (mailto)": r"mailto:[^\s\"'<>]+",
        "Phone (tel link)": r"tel:[^\s\"'<>]+",
    }

    found = []
    for label, pattern in patterns.items():
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            found.append(f"{label}: {matches[0]}")

    return found


def get_webpage_info(domain: str) -> dict:
    """
    Webpage ko actually fetch karke uski jaankari nikalta hai:
    - Status code (page khul raha hai ya nahi)
    - Page title
    - Server software (jaise Apache, Nginx, cloudflare)
    - HTTPS/SSL hai ya nahi
    - Important response headers
    """
    result = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            result["url"] = response.url
            result["scheme"] = scheme.upper()
            result["status_code"] = response.status_code
            result["server"] = response.headers.get("Server", "Not disclosed")
            result["powered_by"] = response.headers.get("X-Powered-By", "Not disclosed")
            result["content_type"] = response.headers.get("Content-Type", "Unknown")

            # Page title nikalna (bina extra library ke, simple tarike se)
            html = response.text
            start = html.lower().find("<title>")
            end = html.lower().find("</title>")
            if start != -1 and end != -1:
                result["title"] = html[start + 7:end].strip()
            else:
                result["title"] = "Title nahi mila"

            # Social media / contact links dhoondhna
            result["social_links"] = get_social_links(html)

            return result  # pehli successful koshish par ruk jao
        except requests.RequestException as e:
            result["error"] = str(e)
            continue  # https fail ho to http try karo

    return result


def print_section(title: str):
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)


def main():
    user_input = input("IP address ya Domain name daalein (jaise 8.8.8.8 ya google.com): ").strip()

    if not user_input:
        print("Kuch input nahi diya gaya. Program band kiya ja raha hai.")
        return

    domain = None
    ip = None

    if is_ip_address(user_input):
        ip = user_input
    else:
        domain = user_input
        ip = resolve_domain_to_ip(domain)
        if ip is None:
            print(f"'{domain}' resolve nahi ho saka. Sahi domain name daalein.")
            return

    # ---------- IP Information ----------
    print_section("IP INFORMATION")
    ip_data = get_ip_info(ip)
    if "error" in ip_data:
        print(f"IP info nahi mil saki: {ip_data['error']}")
    else:
        print(f"IP Address      : {ip_data.get('query')}")
        print(f"Owner / ISP     : {ip_data.get('isp')}")
        print(f"Organization    : {ip_data.get('org')}")
        print(f"Hosting / ASN   : {ip_data.get('as')}")
        print(f"City            : {ip_data.get('city')}")
        print(f"Region          : {ip_data.get('regionName')}")
        print(f"Country         : {ip_data.get('country')}")
        print(f"Postal Code     : {ip_data.get('zip')}")
        print(f"Timezone        : {ip_data.get('timezone')}")
        print(f"Latitude        : {ip_data.get('lat')}")
        print(f"Longitude       : {ip_data.get('lon')}")

    # ---------- Domain WHOIS Information ----------
    if domain:
        print_section("DOMAIN INFORMATION (WHOIS)")
        domain_data = get_domain_whois(domain)
        if "error" in domain_data:
            print(f"Domain info nahi mil saki: {domain_data['error']}")
        else:
            print(f"Domain Name        : {domain_data.get('domain_name')}")
            print(f"Registrar          : {domain_data.get('registrar')}")
            print(f"Start Time (Created): {domain_data.get('creation_date')}")
            print(f"Expiry Time         : {domain_data.get('expiration_date')}")
            print(f"Last Updated        : {domain_data.get('updated_date')}")
            print(f"Name Servers (Hosting Server): {domain_data.get('name_servers')}")
            print(f"Organization        : {domain_data.get('org')}")
            print(f"Country             : {domain_data.get('country')}")
            print(f"Abuse Contact Email : {domain_data.get('abuse_email') or 'Publicly available nahi hai'}")

        # ---------- SSL Certificate Information ----------
        print_section("SSL CERTIFICATE INFORMATION")
        ssl_data = get_ssl_info(domain)
        if "error" in ssl_data:
            print(f"SSL info nahi mil saki: {ssl_data['error']}")
            print("(Ho sakta hai website HTTPS support na karti ho)")
        else:
            print(f"Issued To (Domain) : {ssl_data.get('issued_to')}")
            print(f"Issued By (CA)      : {ssl_data.get('issued_by')}")
            print(f"Valid From          : {ssl_data.get('valid_from')}")
            print(f"Valid Until (Expiry): {ssl_data.get('valid_until')}")

        # ---------- Webpage Information ----------
        print_section("WEBPAGE INFORMATION")
        page_data = get_webpage_info(domain)
        if "status_code" in page_data:
            print(f"URL              : {page_data.get('url')}")
            print(f"Protocol         : {page_data.get('scheme')}")
            print(f"Status Code      : {page_data.get('status_code')}")
            print(f"Page Title       : {page_data.get('title')}")
            print(f"Server Software  : {page_data.get('server')}")
            print(f"Powered By       : {page_data.get('powered_by')}")
            print(f"Content Type     : {page_data.get('content_type')}")

            social = page_data.get("social_links", [])
            print("\nSocial Media / Contact Links (webpage par mile):")
            if social:
                for link in social:
                    print(f"  - {link}")
            else:
                print("  Koi social media/contact link nahi mila")
        else:
            print(f"Webpage open nahi ho saki: {page_data.get('error', 'Unknown error')}")
    else:
        print("\nNote: Aapne sirf IP address diya hai. WHOIS (start/expiry time)")
        print("sirf domain name ke liye available hota hai, IP ke liye nahi.")
        print("Agar aap webpage ka registration/expiry dekhna chahte hain to")
        print("us website ka domain name (jaise example.com) daalein.")


if __name__ == "__main__":
    main()
