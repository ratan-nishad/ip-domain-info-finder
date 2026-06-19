# 🔍 IP / Domain Information Finder

A Python tool that takes an **IP address** or **domain name** and returns detailed information about it — including geolocation, ISP/owner, domain WHOIS data (registration & expiry dates), SSL certificate details, and webpage metadata.

Available in two versions:
- **CLI version** (`ip_domain_info.py`) — runs in the terminal
- **Web version** (`app.py`) — Flask-based local web app with a browser UI

---

## ✨ Features

- 🌐 **IP Information** — ISP/owner, organization, hosting provider (ASN), city, region, country, timezone, coordinates
- 📄 **Domain WHOIS Info** — registrar, creation date (start time), expiration date, name servers, abuse contact email
- 🔒 **SSL Certificate Info** — issuing Certificate Authority, validity period
- 🖥️ **Webpage Info** — HTTP status code, page title, server software, content type
- 🔗 **Social Media / Contact Links** — automatically detects publicly listed social links (Facebook, Instagram, Twitter/X, LinkedIn, YouTube, WhatsApp, Telegram) and contact info on the target webpage

---

## 📸 Screenshots

### CLI Version
![CLI output - IP & Domain info](screenshots/cli-version-output-1.png)
![CLI output - SSL & Webpage info](screenshots/cli-version-output-2.png)

### Web Version (Flask)
**Server running on localhost:**
![Flask server running](screenshots/terminal-server-start.png)

**IP Information panel:**
![Web UI - IP Information](screenshots/web-ip-info.png)

**Domain, SSL & Webpage Information panel:**
![Web UI - Domain SSL Webpage](screenshots/web-domain-ssl-webpage.png)

---

## ⚙️ Installation

```bash
git clone https://github.com/<your-username>/ip-domain-info-finder.git
cd ip-domain-info-finder

python3 -m venv myenv
source myenv/bin/activate      # On Windows: myenv\Scripts\activate

pip install -r requirements.txt
```

---

## 🚀 Usage

### CLI Version

```bash
python3 ip_domain_info.py
```

You'll be prompted to enter an IP address or domain name, e.g. `8.8.8.8` or `google.com`.

### Web Version

```bash
python3 app.py
```

Then open your browser at:

```
http://127.0.0.1:5000
```

Enter a domain or IP into the search box and view the results in the browser.

---

## 🛠️ Tech Stack

- Python 3
- [Flask](https://flask.palletsprojects.com/) — web server
- [requests](https://docs.python-requests.org/) — HTTP requests & [ip-api.com](https://ip-api.com) for geolocation
- [python-whois](https://pypi.org/project/python-whois/) — domain WHOIS lookups
- Python's built-in `ssl` module — SSL certificate inspection

---

## ⚠️ Disclaimer

This tool only retrieves **publicly available** technical information (IP geolocation, domain WHOIS records, SSL certificates, and publicly listed contact/social links on webpages). It does **not** and cannot retrieve private personal information such as an individual's phone number, personal email, or real name, as that data is protected by privacy regulations (e.g. GDPR) and is not exposed through public APIs.

Use this tool responsibly and only for legitimate purposes such as research, security auditing of your own infrastructure, or educational learning.

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
