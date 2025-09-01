# Web-Based Security Toolkit (intelligent portal)

A **web-based security toolkit** designed to assist in **threat intelligence, URL scanning, and malware analysis** through an interactive dashboard and intelligent reporting system.

## 🚀 Features

### 🔗 URL Scanner Dashboard
- Scans and analyzes submitted URLs.
- Integrates multiple threat intelligence sources:
  - [VirusTotal](https://www.virustotal.com/)  
  - [Google Safe Browsing](https://safebrowsing.google.com/)  
  - [Cisco Talos Intelligence](https://talosintelligence.com/)  
  - [MalwareBazaar](https://bazaar.abuse.ch/)  
- Extracts WHOIS information, domain names, IP addresses, and subdomains.  
- Performs HTML analysis for suspicious keywords.  
- Generates an **intelligent safety score** (Harmless / Suspicious / Malicious).  
- Provides interactive reports 

### 🦠 Malware Analysis Dashboard *(In Progress)*
- Rule-based malware detection using **YARA rules**.  
- Hash-based malware detection (MD5, SHA1, SHA256).  
- Planned integration with **MalwareBazaar** for known malware samples.  
- Intelligent malware reports with real-time analysis.  

## 🛠️ Tech Stack
- **Frontend:** Interactive UI-based dashboard (Flask + HTML/CSS/JS)  
- **Backend:** Python  
- **APIs:** VirusTotal, Google Safe Browsing, Cisco Talos, MalwareBazaar  
- **Threat Intelligence:** WHOIS, Subdomain Enumeration, YARA  

## 📊 Reports
- Interactive security reports available through the dashboard.  
- Option to view past reports for deeper investigation.  

## 📂 Project Status
- ✅ URL Scanner Dashboard – Completed  
- 🔄 Malware Analysis Dashboard – In Progress  

## 📌 Future Enhancements
- Advanced malware sandboxing  
- More threat intel API integrations  
- Exportable PDF/CSV reports  

## 👨‍💻 Author
Developed by **[Raahim Mahmooth](https://www.linkedin.com/in/raahim-mahmooth/)**  
[GitHub Repository Link](https://github.com/raahimmahmooth/Intelligent-portal)
