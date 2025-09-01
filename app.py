import asyncio

from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os
from datetime import datetime
import uuid

from scanner import (
    STORE_REPORT,
    fetch_url_content,
    get_domain,
    resolve_ip,
    domain_main_or_sub,
    whois_info,
    virustotal_domain_check,
    virustotal_subdomains,
    google_safe_browsing_check,
    analyze_html,
    save_report,
    capture_snapshot
)

try:
    from scanner import score_from_findings
except Exception:
    def score_from_findings(vt_stats, gsb_matches, html_analysis):
        score = 0
        if isinstance(vt_stats, dict):
            score += vt_stats.get('malicious', 0) * 20
            score += vt_stats.get('suspicious', 0) * 10
        if gsb_matches:
            score += 60
        score += min(30, len(html_analysis.get('suspicious_keywords', [])) * 10)
        return min(100, score)

app = Flask(__name__)


@app.route("/")
def welcome():
    return render_template("welcome.html")


@app.route("/scanner_dashboard")
def scanner_dashboard():
    reports = [os.path.splitext(f)[0] for f in os.listdir(STORE_REPORT) if f.endswith(".html")]
    reports.sort(reverse=True)
    return render_template("Scanner_Dashboard.html", reports=reports)


@app.route("/malware_dashboard")
def malware_dashboard():
    return render_template("malware_analysis_dashboard.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url")
    if not url:
        return redirect(url_for("scanner_dashboard"))
    unique_id = str(uuid.uuid4())
    html, final_url, status, headers, encoding, elapsed, redirect_history, content_length = fetch_url_content(url)

    domain = get_domain(final_url or url)
    ip = resolve_ip(domain) or "N/A"
    domain_type, main_domain = domain_main_or_sub(domain)
    who = whois_info(main_domain)
    vt = virustotal_domain_check(main_domain)
    subs = virustotal_subdomains(main_domain)
    gsb = google_safe_browsing_check(final_url or url)
    html_info = analyze_html(html)
    score = score_from_findings(vt.get("stats", {}), gsb.get("matches"), html_info)

    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "original_url": url,
        "final_url": final_url,
        "domain": domain,
        "main_domain": main_domain,
        "ip": ip,
        "domain_type": domain_type,
        "whois": who,
        "virustotal": vt,
        "subdomains": subs[:50],
        "gsb": gsb,
        "html": html_info,
        "score": score,
        "status_code": status,
        "headers": headers,
        "encoding": encoding,
        "elapsed_time": elapsed,
        "redirect_history": redirect_history,
        "content_length": content_length,
    }

    # ...existing code...

    # Capture snapshot first
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    snapshot_path = loop.run_until_complete(capture_snapshot(final_url or url, unique_id))
    # Always set snapshot path to Flask route, regardless of what capture_snapshot returns
    data["snapshot"] = f"/reports/snapshots/{unique_id}.png"

    # Save report once, after snapshot
    report_id = save_report(data, unique_id)

    # Automatic cleanup: delete all previous reports and snapshots except the current one
    for fname in os.listdir(STORE_REPORT):
        if (fname.endswith('.html') or fname.endswith('.json')) and not fname.startswith(f'scan_{unique_id}'):
            try:
                os.remove(os.path.join(STORE_REPORT, fname))
            except Exception:
                pass
    snapshot_dir = os.path.join(STORE_REPORT, "snapshots")
    if os.path.exists(snapshot_dir):
        for fname in os.listdir(snapshot_dir):
            if fname != f'{unique_id}.png':
                try:
                    os.remove(os.path.join(snapshot_dir, fname))
                except Exception:
                    pass

    return redirect(url_for("report_ready", report_id=report_id))

#@app.route("/reports/<report_id>.json")
#def get_report_json(report_id):
 #   path = os.path.join(STORE_REPORT, f"{report_id}.json")
  #  if not os.path.exists(path):
   #     return "Not found", 404
    #return send_from_directory(STORE_REPORT, f"{report_id}.json")


@app.route("/reports/<report_id>.html")
def report(report_id):
    path = os.path.join(STORE_REPORT, f"{report_id}.html")
    if not os.path.exists(path):
        return "Not found", 404
    return send_from_directory(STORE_REPORT, f"{report_id}.html")

@app.route("/reports/snapshots/<filename>")
def report_snapshot(filename):
    return send_from_directory(os.path.join(STORE_REPORT, "snapshots"), filename)


# New route for stateless report ready page
@app.route("/report_ready/<report_id>")
def report_ready(report_id):
    path = os.path.join(STORE_REPORT, f"{report_id}.html")
    if not os.path.exists(path):
        return "Not found", 404
    return render_template("report_ready.html", report_id=report_id)

if __name__ == "__main__":
    app.run(debug=True)
