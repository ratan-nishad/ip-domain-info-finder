#!/usr/bin/env python3
"""
IP / Domain Information Finder - WEB VERSION (Flask)
-------------------------------------------------------
Ye terminal-wale program ka hi web version hai. Browser khol kar
domain/IP daal sakte hain aur result wahi browser me dikhega.

Requirements (pehle install karein):
    pip install flask requests python-whois

Run karne ka tarika:
    python3 app.py

Phir browser me ye URL kholein:
    http://127.0.0.1:5000
"""

import socket
import ssl
import re
import sys
from datetime import datetime

try:
    from flask import Flask, render_template_string, request
except ImportError:
    print("Error: 'flask' library install nahi hai.")
    print("Install karein: pip install flask")
    sys.exit(1)

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


app = Flask(__name__)


# ===================== SAARE FUNCTIONS (terminal wale jaise) =====================

def is_ip_address(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def resolve_domain_to_ip(domain: str):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_ip_info(ip: str) -> dict:
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
    if whois is None:
        return {"error": "'python-whois' library install nahi hai."}
    try:
        w = whois.whois(domain)
        abuse_email = None
        emails = w.emails
        if emails:
            email_list = [emails] if isinstance(emails, str) else emails
            for e in email_list:
                if "abuse" in e.lower():
                    abuse_email = e
                    break
            if abuse_email is None and email_list:
                abuse_email = email_list[0]

        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,
            "abuse_email": abuse_email,
            "org": w.org,
            "country": w.country,
        }
    except Exception as e:
        return {"error": str(e)}


def get_ssl_info(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

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

            html = response.text
            start = html.lower().find("<title>")
            end = html.lower().find("</title>")
            result["title"] = html[start + 7:end].strip() if start != -1 and end != -1 else "Title nahi mila"
            result["social_links"] = get_social_links(html)
            return result
        except requests.RequestException as e:
            result["error"] = str(e)
            continue
    return result


# ===================== HTML TEMPLATE =====================

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="hi">
<head>
<meta charset="UTF-8">
<title>IP / Domain Information Finder</title>
<style>
  body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 30px; }
  .container { max-width: 800px; margin: auto; }
  h1 { color: #38bdf8; }
  form { display: flex; gap: 10px; margin-bottom: 30px; }
  input[type=text] { flex: 1; padding: 10px; border-radius: 6px; border: none; font-size: 16px; }
  button { padding: 10px 20px; border: none; border-radius: 6px; background: #38bdf8; color: #0f172a; font-weight: bold; cursor: pointer; }
  button:hover { background: #0ea5e9; }
  .section { background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
  .section h2 { color: #facc15; margin-top: 0; }
  .row { display: flex; padding: 4px 0; border-bottom: 1px solid #334155; }
  .label { width: 220px; color: #94a3b8; }
  .value { flex: 1; word-break: break-all; }
  .error { color: #f87171; }
  ul { padding-left: 20px; }
</style>
</head>
<body>
<div class="container">
  <h1>🔍 IP / Domain Information Finder</h1>
  <form method="POST">
    <input type="text" name="user_input" placeholder="IP ya domain daalein, jaise google.com" value="{{ user_input or '' }}" required>
    <button type="submit">Search</button>
  </form>

  {% if error %}
    <div class="section error">{{ error }}</div>
  {% endif %}

  {% if ip_data %}
  <div class="section">
    <h2>🌐 IP Information</h2>
    {% if ip_data.error %}
      <p class="error">{{ ip_data.error }}</p>
    {% else %}
      <div class="row"><div class="label">IP Address</div><div class="value">{{ ip_data.query }}</div></div>
      <div class="row"><div class="label">Owner / ISP</div><div class="value">{{ ip_data.isp }}</div></div>
      <div class="row"><div class="label">Organization</div><div class="value">{{ ip_data.org }}</div></div>
      <div class="row"><div class="label">Hosting / ASN</div><div class="value">{{ ip_data.as }}</div></div>
      <div class="row"><div class="label">City</div><div class="value">{{ ip_data.city }}</div></div>
      <div class="row"><div class="label">Region</div><div class="value">{{ ip_data.regionName }}</div></div>
      <div class="row"><div class="label">Country</div><div class="value">{{ ip_data.country }}</div></div>
      <div class="row"><div class="label">Postal Code</div><div class="value">{{ ip_data.zip }}</div></div>
      <div class="row"><div class="label">Timezone</div><div class="value">{{ ip_data.timezone }}</div></div>
    {% endif %}
  </div>
  {% endif %}

  {% if domain_data %}
  <div class="section">
    <h2>📄 Domain Information (WHOIS)</h2>
    {% if domain_data.error %}
      <p class="error">{{ domain_data.error }}</p>
    {% else %}
      <div class="row"><div class="label">Domain Name</div><div class="value">{{ domain_data.domain_name }}</div></div>
      <div class="row"><div class="label">Registrar</div><div class="value">{{ domain_data.registrar }}</div></div>
      <div class="row"><div class="label">Start Time</div><div class="value">{{ domain_data.creation_date }}</div></div>
      <div class="row"><div class="label">Expiry Time</div><div class="value">{{ domain_data.expiration_date }}</div></div>
      <div class="row"><div class="label">Name Servers</div><div class="value">{{ domain_data.name_servers }}</div></div>
      <div class="row"><div class="label">Organization</div><div class="value">{{ domain_data.org }}</div></div>
      <div class="row"><div class="label">Abuse Contact</div><div class="value">{{ domain_data.abuse_email or 'Available nahi' }}</div></div>
    {% endif %}
  </div>
  {% endif %}

  {% if ssl_data %}
  <div class="section">
    <h2>🔒 SSL Certificate</h2>
    {% if ssl_data.error %}
      <p class="error">{{ ssl_data.error }}</p>
    {% else %}
      <div class="row"><div class="label">Issued To</div><div class="value">{{ ssl_data.issued_to }}</div></div>
      <div class="row"><div class="label">Issued By (CA)</div><div class="value">{{ ssl_data.issued_by }}</div></div>
      <div class="row"><div class="label">Valid From</div><div class="value">{{ ssl_data.valid_from }}</div></div>
      <div class="row"><div class="label">Valid Until</div><div class="value">{{ ssl_data.valid_until }}</div></div>
    {% endif %}
  </div>
  {% endif %}

  {% if page_data %}
  <div class="section">
    <h2>🖥️ Webpage Information</h2>
    {% if page_data.error and not page_data.status_code %}
      <p class="error">{{ page_data.error }}</p>
    {% else %}
      <div class="row"><div class="label">URL</div><div class="value">{{ page_data.url }}</div></div>
      <div class="row"><div class="label">Status Code</div><div class="value">{{ page_data.status_code }}</div></div>
      <div class="row"><div class="label">Page Title</div><div class="value">{{ page_data.title }}</div></div>
      <div class="row"><div class="label">Server Software</div><div class="value">{{ page_data.server }}</div></div>
      <div class="row"><div class="label">Powered By</div><div class="value">{{ page_data.powered_by }}</div></div>
      <p style="color:#94a3b8; margin-top:15px;">Social Media / Contact Links:</p>
      <ul>
        {% for link in page_data.social_links %}
          <li>{{ link }}</li>
        {% else %}
          <li>Koi social link nahi mila</li>
        {% endfor %}
      </ul>
    {% endif %}
  </div>
  {% endif %}
</div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    context = {}
    if request.method == "POST":
        user_input = request.form.get("user_input", "").strip()
        context["user_input"] = user_input

        if not user_input:
            context["error"] = "Kuch input nahi diya gaya."
            return render_template_string(PAGE_TEMPLATE, **context)

        domain = None
        ip = None

        if is_ip_address(user_input):
            ip = user_input
        else:
            domain = user_input
            ip = resolve_domain_to_ip(domain)
            if ip is None:
                context["error"] = f"'{domain}' resolve nahi ho saka."
                return render_template_string(PAGE_TEMPLATE, **context)

        context["ip_data"] = get_ip_info(ip)

        if domain:
            context["domain_data"] = get_domain_whois(domain)
            context["ssl_data"] = get_ssl_info(domain)
            context["page_data"] = get_webpage_info(domain)

    return render_template_string(PAGE_TEMPLATE, **context)


if __name__ == "__main__":
    print("Server start ho raha hai...")
    print("Browser me ye URL kholein: http://127.0.0.1:5000")
    app.run(debug=True, host="127.0.0.1", port=5000)
