import traceback

from idna.idnadata import scripts
from soupsieve.util import lower
import requests ;'fetching URL/API'
import bs4;'parsing HTML content'
import socket;'DNS resolution'
import tldextract;'extract the domain'
import whois; 'for information'
import json; 'report'
import os
from datetime import datetime
from dotenv import load_dotenv;'load API keys'
from urllib.parse import urlparse
import json
import re
#snapshot
import asyncio
from pyppeteer import launch

load_dotenv()
VT_API_KEY =os.getenv('VT_API_KEY')
GSB_API_KEY=os.getenv('GSB_API_KEY')

STORE_REPORT=os.path.join(os.path.dirname(__file__),'reports')
if not os.path.exists(STORE_REPORT):
    os.makedirs(STORE_REPORT)

"returning the domain"
def get_domain(url):
    try:
        parsed=urlparse(url)
        return parsed.netloc.lower()
    except:
        return 'parsing fail'

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return

def domain_main_or_sub(domain):
    ext=tldextract.extract(domain)
    main=f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain# ext.subdomain = "blog" ext.domain = "example"  ext.suffix = "co.uk"
    if domain==main :
        return 'main', main
    return 'subdomain',main

def fetch_url_content(url, timeout=12):
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'})

        return (
            resp.text,  # HTML content
            resp.url,  # Final URL after redirects
            resp.status_code,  # HTTP status code
            dict(resp.headers),  # Headers
            resp.encoding,  # Encoding
            resp.elapsed.total_seconds(),  # Time taken
            #resp.cookies.get_dict(),  # Cookies
            [h.url for h in resp.history],  # Redirect history
            len(resp.content)  # Content length in bytes
        )

    except Exception as e:
        return None, None, str(e), None, None, None, None, None



SNAPSHOT_DIR = os.path.join(STORE_REPORT, "snapshots")
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

from pyppeteer import launch
import os

SNAPSHOT_DIR = os.path.join(STORE_REPORT, "snapshots")
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

async def capture_snapshot(url, report_id):

    try:
        # Specify the path to your installed Chrome
        chrome_path = "C:/Program Files/Google/Chrome/Application/chrome.exe"  # Windows example
        # For Linux: '/usr/bin/google-chrome' or '/usr/bin/chromium-browser'
        # For Mac: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

        browser = await launch(
            executablePath=chrome_path,
            headless=True,
            handleSIGINT=False,
            handleSIGTERM=False,
            handleSIGHUP=False,
            args=["--no-sandbox"]
        )
        page = await browser.newPage()
        await page.setViewport({"width": 1280, "height": 800})
        await page.goto(url, {"waitUntil": "networkidle2", "timeout": 60000})
        path = os.path.join(SNAPSHOT_DIR, f"{report_id}.png")
        await page.screenshot({"path": path, "fullPage": True})
        await browser.close()
        rel_path = os.path.relpath(path, STORE_REPORT)  # makes "screenshots/xxxx.png"
        return rel_path

    except Exception as e:
        print(f"[ERROR] {e}")
        traceback.print_exc()
        return None




def analyze_html(html):
    if not html:
        return {'suspicious_keywords': [], 'no_of_scripts': 0}
    html_breakdown = bs4.BeautifulSoup(html, 'html.parser')
    suspicious_keywords = ["eval", "document.write", "atob", "setTimeout", "iframe", "onerror", "window.location"]
    word_found = set()
    scripts = html_breakdown.find_all('script')
    for each_script in scripts:
        code = each_script.get_text() or ''
        for word in suspicious_keywords:
            if word in code:
                word_found.add(word)
    return {'suspicious_keywords': list(word_found), 'no_of_scripts': len(scripts)}

def virustotal_domain_check(domain):
    if not VT_API_KEY:
        return {'error':'The API key is missing'}#error handling
    headers={'x-apikey':VT_API_KEY}
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    try:
        req=requests.get(url,headers=headers)
        if req.status_code == 200 :
            data = req.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {'ok': True, 'stats': stats}
        return {'ok':False,'status_code':req.status_code}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

#getting th subdomain
def virustotal_subdomains(domain):
    if not VT_API_KEY:
        return []
    headers = {'x-apikey': VT_API_KEY}
    url = f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
    subs = []
    try:
        req = requests.get(url, headers=headers)
        if req.status_code == 200:
            data = req.json()
            for item in data.get('data', []):
                subs.append(item.get('id'))
    except Exception:
        pass
    return subs


#checking a URL against Google Safe Browsing
def google_safe_browsing_check(url):
    if not GSB_API_KEY:
        return {'error': 'GSB API key missing'}

    api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}'
    body = {
        "client": {
            "clientId": "custom-scanner",
            "clientVersion": "1.0"  # keeping it fixed, avoids rejection by API
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(api_url, json=body)
        if resp.status_code != 200:
            return {'error': f"API error {resp.status_code}"}

        result = resp.json()
        threats = []

        if "matches" in result:
            for match in result["matches"]:
                threats.append({
                    "threatType": match.get("threatType", "Unknown"),
                    "platformType": match.get("platformType", "Unknown"),
                    "threatEntryType": match.get("threatEntryType", "Unknown"),
                    "url": match.get("threat", {}).get("url", url),
                    "malware_family": next(
                        (e.get("value") for e in match.get("threatEntryMetadata", {}).get("entries", [])
                         if e.get("key") == "malware_family"), None
                    )
                })

        return {"matches": threats} if threats else {"matches": []}

    except Exception as e:
        return {'error': str(e)}


# checking the domain legitimacy

#checking the domain legitimacy
def whois_info(domain):
    try:
        who = whois.whois(domain)
        created = who.creation_date
        expiry = who.expiration_date

        #if there are multiple creation/expiry dates, take the first one
        if isinstance(created, list):
            created = created[0]
        if isinstance(expiry, list):
            expiry = expiry[0]

        return {
            'ok': True,
            'creation_date': str(created) if created else None,
            'expiration_date': str(expiry) if expiry else None,
            'registrar': getattr(who, 'registrar', None),
            'country': getattr(who, 'country', None),
            'city': getattr(who, 'city', None)
        }

    except Exception as e:
        return {'ok': False, 'error': str(e)}


def save_report(data, safe_ts):
    filename = f'scan_{safe_ts}'
    json_path = os.path.join(STORE_REPORT, f"{filename}.json")
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)

    html_path = os.path.join(STORE_REPORT, f"{filename}.html")
    with open(html_path, 'w') as f:
        f.write(render_report_html(data))

    return filename


def pretty_json(data):
    json_str = json.dumps(data, indent=2, sort_keys=True)
    json_str = re.sub(r'("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(?=\s*:))', r'<span class="json-key">\1</span>', json_str)
    json_str = re.sub(r'("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(?!\s*:))', r'<span class="json-string">\1</span>', json_str)
    json_str = re.sub(r'\b(true|false)\b', r'<span class="json-bool">\1</span>', json_str)
    json_str = re.sub(r'\b(null)\b', r'<span class="json-null">\1</span>', json_str)
    json_str = re.sub(r'([-]?\d+(\.\d+)?)', r'<span class="json-number">\1</span>', json_str)
    return json_str

def render_report_html(data):
    score = data.get('score', 0)
    if score >= 70:
        color = '#ff4d4d'
        verdict = 'Malicious'
    elif score >= 30:
        color = '#ffcc00'
        verdict = 'Suspicious'
    else:
        color = '#66cc66'
        verdict = 'Likely Safe'

    def render_safe_browsing_html(gsb_data):
        if not gsb_data:
            return "<p style='color:green;'>No Google Safe Browsing data available.</p>"
        if "error" in gsb_data:
            return f"<p style='color:red;'>Error: {gsb_data['error']}</p>"
        if not gsb_data.get("matches", []):
            return "<p style='color:green;'>No threats detected by Google Safe Browsing.</p>"

        # If threats detected, show red warning
        gsb_html = "<p style='color:red; font-weight:bold;'>Google Safe Browsing detected one or more threats!</p>"
        gsb_html += "<table border='1' cellpadding='5' style='border-collapse: collapse;'>"
        gsb_html += "<tr><th>Threat Type</th><th>Platform</th><th>URL</th><th>Malware Family</th></tr>"

        for match in gsb_data.get("matches", []):
            gsb_html += "<tr>"
            gsb_html += f"<td>{match.get('threatType', 'N/A')}</td>"
            gsb_html += f"<td>{match.get('platformType', 'N/A')}</td>"
            gsb_html += f"<td>{match.get('url', 'N/A')}</td>"
            gsb_html += f"<td>{match.get('malware_family', 'N/A')}</td>"
            gsb_html += "</tr>"

        gsb_html += "</table>"
        return gsb_html

    def render_virustotal_html(vt_data):
        if not vt_data:
            return "<p style='color:green;'>No VirusTotal data available.</p>"

        if "error" in vt_data:
            return f"<p style='color:red;'>Error: {vt_data['error']}</p>"

        stats = vt_data.get("stats", {})
        if not stats or (stats.get("malicious", 0) == 0 and stats.get("suspicious", 0) == 0):
            return "<p style='color:green;'>No threats detected by VirusTotal.</p>"

        # If threats detected, show red warning + table
        vt_html = "<p style='color:red; font-weight:bold;'> VirusTotal detected one or more threats!</p>"
        vt_html += "<table border='1' cellpadding='5' style='border-collapse: collapse;'>"
        vt_html += "<tr><th>Type</th><th>Count</th></tr>"
        for k, v in stats.items():
            vt_html += f"<tr><td>{k}</td><td>{v}</td></tr>"
        vt_html += "</table>"

        return vt_html

    html = f"""
    <!doctype html>
    <html lang='en'>
    <head>
        <meta charset='utf-8'>
        <title>Scan Report - {data.get('domain')}</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' rel='stylesheet'>
        <link href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css' rel='stylesheet'>
        <link href='https://fonts.googleapis.com/css2?family=Montserrat:wght@700;900&display=swap' rel='stylesheet'>
        <style>
            body {{
                min-height: 100vh;
                background: linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%);
                font-family: 'Montserrat', Arial, sans-serif;
                color: #fff;
                position: relative;
                overflow-x: hidden;
                padding: 0;
            }}
            .cyber-grid {{
                position: fixed;
                top: 0; left: 0; width: 100vw; height: 100vh;
                z-index: 0;
                pointer-events: none;
                background: repeating-linear-gradient(90deg, rgba(0,255,255,0.07) 0 2px, transparent 2px 40px),
                            repeating-linear-gradient(180deg, rgba(0,255,255,0.07) 0 2px, transparent 2px 40px);
                animation: gridmove 8s linear infinite;
            }}
            @keyframes gridmove {{
                0% {{ background-position: 0 0, 0 0; }}
                100% {{ background-position: 40px 40px, 40px 40px; }}
            }}
            .glass-card {{
                background: rgba(20, 40, 60, 0.80);
                border-radius: 1.5rem;
                box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.22);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border: 2.5px solid rgba(0,255,255,0.22);
                padding: 3.2rem 3.2rem 2.7rem 3.2rem;
                margin: 3.5rem auto 2.5rem auto;
                max-width: 700px;
                z-index: 1;
            }}
                        .main-heading {{
                                color: #00ffe7;
                                font-size: 2.1rem;
                                font-weight: 900;
                                letter-spacing: 1px;
                                text-align: center;
                                margin-bottom: 0.7rem;
                                font-family: 'Montserrat', Arial, sans-serif;
                        }}
                        .summary-section {{
                                background: rgba(0,255,231,0.08);
                                border: 1.5px solid #00ffe7;
                                border-radius: 0.9rem;
                                padding: 1.1rem 1.2rem 0.7rem 1.2rem;
                                margin-bottom: 1.5rem;
                                box-shadow: 0 2px 8px #00ffe71a;
                        }}
                        .summary-section h4 {{
                                color: #00ffe7;
                                font-size: 1.18rem;
                                font-weight: 800;
                                margin-bottom: 0.7rem;
                        }}
                        .verdict {{
                                background-color: {color};
                                color: #222;
                                padding: 10px 18px;
                                border-radius: 8px;
                                font-size: 1.18em;
                                font-weight: 800;
                                margin: 1.2rem auto 1.7rem auto;
                                text-align: center;
                                max-width: 350px;
                                box-shadow: 0 2px 12px #00ffe7a0;
                        }}
                        .section {{
                                background: rgba(30, 40, 60, 0.92);
                                padding: 1.3rem 1.2rem 1.1rem 1.2rem;
                                border-radius: 1rem;
                                margin-bottom: 1.3rem;
                                box-shadow: 0 2px 8px #00ffe71a;
                                border: 1px solid rgba(0,255,255,0.08);
                        }}
                        .section h3 {{
                                color: #00ffe7;
                                font-size: 1.18rem;
                                font-weight: 800;
                                margin-bottom: 0.7rem;
                        }}
                        .callout {{
                                background: rgba(255,77,77,0.13);
                                border-left: 4px solid #ff4d4d;
                                padding: 0.7rem 1rem;
                                border-radius: 0.6rem;
                                margin-bottom: 1rem;
                                color: #ffb3b3;
                                font-weight: 700;
                                font-size: 1.05rem;
                        }}
                        .callout.safe {{
                                background: rgba(102,204,102,0.13);
                                border-left: 4px solid #66cc66;
                                color: #b5f7b5;
                        }}
                        .callout.suspicious {{
                                background: rgba(255,204,0,0.13);
                                border-left: 4px solid #ffcc00;
                                color: #ffe699;
                        }}
                        pre {{
                                background: #1e1e2f;
                                color: #f8f8f2;
                                padding: 10px;
                                border-radius: 7px;
                                overflow-x: auto;
                                font-size: 0.98em;
                                margin-bottom: 0;
                        }}
                        table {{ width: 100%; border-collapse: collapse; margin-bottom: 0.7rem; }}
                        th, td {{ border: 1px solid #00ffe7; padding: 8px; }}
                        th {{ background-color: #0f2027; color: #00ffe7; }}
                        .json-key {{ color: #9cdcfe; }}
                        .json-string {{ color: #ce9178; }}
                        .json-number {{ color: #b5cea8; }}
                        .json-bool {{ color: #569cd6; }}
                        .json-null {{ color: #808080; }}
                        details summary {{ color: #00ffe7; cursor: pointer; }}
                        a {{ color: #00ffe7; }}
                </style>
        </head>
        <body>
            <div class='cyber-grid'></div>
            <div class='container position-relative' style='z-index:1;'>
                <div class='glass-card mt-5'>
                    <div class='main-heading'>Scan Report</div>
                    <div class='text-center mb-3' style='font-size:1.08rem; color:#b2bec3;'>URL: <span style='color:#00ffe7;'>{data.get('original_url')}</span></div>
                    <div class='summary-section'>
                        <h4><i class='fa-solid fa-chart-pie'></i> Summary</h4>
                        <ul style='list-style:none; padding-left:0; margin-bottom:0;'>
                            <li><i class='fa-solid fa-shield-halved'></i> <b>Verdict:</b> <span style='color:{color};'>{verdict}</span> (Score: {score})</li>
                            <li><i class='fa-solid fa-globe'></i> <b>Domain:</b> {data.get('domain')}</li>
                            <li><i class='fa-solid fa-network-wired'></i> <b>IP:</b> {data.get('ip')}</li>
                            <li><i class='fa-solid fa-calendar'></i> <b>Scan Date:</b> {data.get('scan_date', 'N/A')}</li>
                        </ul>
                    </div>
                    <div class="verdict">Verdict: {verdict} (Score: {score})</div>
                    {f"<div class='callout {'safe' if score < 30 else 'suspicious' if score < 70 else ''}'>" +
                        ("No major threats detected. This site appears safe." if score < 30 else
                         "Some suspicious activity detected. Caution advised." if score < 70 else
                         "Malicious indicators found! Avoid this site.") +
                        "</div>"}
                    <div class="section">
                        <h3><i class="fa-solid fa-image"></i> Website Snapshot</h3>
                        {f"<img src='{data.get('snapshot')}' style='max-width:100%; border:1.5px solid #00ffe7; border-radius:0.7rem;' />" if data.get('snapshot') else "<p>No snapshot available.</p>"}
                    </div>
                    <div class="section">
                        <h3><i class="fa-solid fa-globe"></i> Domain Information</h3>
                        <pre>Domain: {data.get('domain')}\nIP: {data.get('ip')}\nDomain Type: {data.get('domain_type')} (main: {data.get('main_domain')})</pre>
                    </div>
                    <div class="section">
                        <h3><i class="fa-solid fa-id-card"></i> WHOIS Information</h3>
                        <pre>Creation Date: {data.get('whois', {}).get('creation_date')}\nRegistrar: {data.get('whois', {}).get('registrar')}</pre>
                    </div>
                    <div class="section">
                        <h3><i class="fa-solid fa-shield-virus"></i> VirusTotal</h3>
                        {render_virustotal_html(data.get('virustotal', {}))}
                        <details><summary>Show Raw VirusTotal Data</summary>
                        <pre>{pretty_json(data.get('virustotal', {}))}</pre></details>
                    </div>
                    <div class="section">
                        <h3><i class="fa-solid fa-shield-halved"></i> Google Safe Browsing</h3>
                        {render_safe_browsing_html(data.get('gsb', {}))}
                        <details><summary>Show Raw GSB Data</summary>
                        <pre>{pretty_json(data.get('gsb', {}))}</pre></details>
                    </div>
                    <div class="section">
                        <h3><i class="fa-solid fa-code"></i> HTML Analysis</h3>
                        <pre>Scripts found: {data.get('html', {}).get('no_of_scripts')}\nSuspicious keywords: {data.get('html', {}).get('suspicious_keywords')}</pre>
                    </div>
                    <div class="section">
                        <h3><i class="fa-solid fa-network-wired"></i> Subdomains (sample)</h3>
                        <pre>{data.get('subdomains')}</pre>
                    </div>
                </div>
                <div class='text-center' style='color:#b2bec3; font-size:0.98rem; margin-top:2.5rem; margin-bottom:1.2rem; z-index:2; position:relative;'>
                    &copy; 2025 Raahim Mahmooth &mdash; Secure Web Toolkit
                </div>
            </div>
        </body>
        </html>
    """
    return html



