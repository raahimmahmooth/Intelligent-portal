# 🔐 Secure Web Toolkit (Intelligent Portal)

A **web-based cybersecurity toolkit** designed to support **threat intelligence, phishing URL analysis, and malware detection**.  
The platform provides an interactive dashboard and generates detailed security reports to aid analysts in evaluating potential threats.  

---

## 🚀 Features

### 🔗 URL Scanner Dashboard
- Scans and analyzes user-submitted URLs.  
- Integrates multiple threat intelligence sources:  
  - [VirusTotal](https://www.virustotal.com/)  
  - [Google Safe Browsing](https://safebrowsing.google.com/)  
  - WHOIS information  
  - Subdomain enumeration  
- Performs **HTML and script inspection** for suspicious keywords.  
- Captures **automated website snapshots** for visual verification.  
- Generates an **intelligent risk score** (*Likely Safe · Suspicious · Malicious*).  
- Produces **interactive, downloadable reports** with embedded screenshots.  

### 🦠 Malware Analysis Dashboard *(In Progress)*
- **Hash-based detection** (MD5, SHA1, SHA256) with planned integration of [MalwareBazaar](https://bazaar.abuse.ch/).  
- **Rule-based detection** using **YARA rules** for malware pattern and IOC matching.  
- Planned capabilities for static analysis: file headers, imports/exports, embedded strings.  
- Interactive malware reporting for clear visibility of findings.  

---

## 🛠️ Tech Stack
- **Backend:** Python (Flask)  
- **Frontend:** HTML · CSS · Bootstrap (cyber-styled UI)  
- **APIs & Integrations:** VirusTotal API · Google Safe Browsing API · WHOIS · (Planned: MalwareBazaar)  
- **Threat Intelligence:** Subdomain Enumeration · HTML Analysis · YARA Rules  

---

## 📊 Reports
- Automatically generated **interactive reports** via the dashboard.  
- Includes:  
  - Domain & IP information  
  - WHOIS details  
  - Threat intelligence results  
  - Subdomains  
  - Risk scoring  
  - Website snapshots  
- Downloadable in **HTML format** for offline use.  

---

## 📂 Project Status
- ✅ **URL Scanner Dashboard** – Completed and deployed  
- 🔄 **Malware Analysis Dashboard** – In progress  

---

## 📌 Roadmap / Future Enhancements
- Advanced malware sandboxing for behavioral analysis.  
- Integration with additional threat intelligence APIs (e.g., Cisco Talos, AbuseIPDB).  
- Exportable **PDF/CSV reports**.  
- User authentication with saved report history.  

---

## 🌐 Live Demo
🔗 [Secure Web Toolkit](https://web-production-6aa3.up.railway.app)  

---

## 👨‍💻 Author
Developed by **[Raahim Mahmooth](https://www.linkedin.com/in/raahim-mahmooth/)**  
Undergraduate Cybersecurity Student | SLIIT  



---
