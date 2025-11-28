# 🔐 API Security Request Validator  
*A Python-based security tool for validating API requests with OWASP & MITRE ATT&CK tagging.*

---

## 📌 Overview

This project is an **API Security Validator** written in Python.  
It analyzes API requests and detects:

✔ Incorrect HTTP methods  
✔ Unknown or unsafe endpoints  
✔ Missing/incorrect headers  
✔ Schema validation failures  
✔ OWASP-style injection attacks (SQLi, XSS)  
✔ Suspicious long inputs  
✔ Weak authentication tokens  
✔ Missing required fields  
✔ Violations mapped to **OWASP Top 10**  
✔ Violations mapped to **MITRE ATT&CK**  
✔ Generates structured security reports  

This tool demonstrates skills required for:

- **Application Security (AppSec)**
- **API Security**
- **Secure Coding**
- **Input validation**
- **Threat detection**
- **Python security tooling**
- **AI/LLM security patterns (input sanitization)**

---

## 🎯 Key Features

### 🔍 API Contract Validation
Ensures requests follow the API rules:
- Allowed HTTP methods  
- Valid endpoints  
- Required request body fields  
- Required headers  
- JSON schema checks (types + length)

### 🛡️ Security Pattern Detection
Detects OWASP Top 10 patterns:
- SQL Injection  
- XSS (browser-based attacks)  
- Large payloads (DoS hint)  
- Broken Authentication  
- Improper Content-Type usage  
- Unknown endpoints  

### 🔗 Security Framework Mappings
Each finding contains:
- **Severity**: LOW / MEDIUM / HIGH  
- **OWASP ID** (e.g., API8:2019 Injection)  
- **MITRE ATT&CK ID** (e.g., T1190)  
- **Check ID** (internal rule tracking)

### 📄 Security Report Generation
Produces a structured report for each request containing:
- Status (VALID / INVALID)  
- Issue count  
- Severity summary  
- Detailed findings  

### 🖥️ CLI Support
You can run validations from:
- Built-in sample requests  
- A JSON file of your own

---

## 🚀 How to Run

### 1️⃣ Install Python  
Make sure you have **Python 3.x** installed.

### 2️⃣ Clone or download the project
```bash
git clone https://github.com/<your-username>/api-request-validator.git
cd api-request-validator
