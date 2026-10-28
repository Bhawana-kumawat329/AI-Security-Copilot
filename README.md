# 🛡️ AI Security Copilot

### AI-Powered Cybersecurity Threat Intelligence & SOC Dashboard

AI Security Copilot is a cybersecurity project designed to help security analysts investigate suspicious IP addresses, domains, URLs, and file hashes through a centralized threat intelligence dashboard. It combines threat intelligence sources, security scanning, risk assessment, and investigation history to support security operations.

## 🚀 Key Features

- **IOC Analysis:** Analyze IP addresses, domains, URLs, and file hashes.
- **Threat Intelligence:** Integrate with VirusTotal and AbuseIPDB to retrieve threat intelligence.
- **IP Intelligence:** Retrieve WHOIS and geolocation information where supported.
- **Security Scanning:** Perform network scanning using Nmap.
- **Vulnerability Intelligence:** Look up relevant CVE information where supported.
- **Risk Assessment:** Calculate risk scores and classify indicators by risk level.
- **Investigation History:** Store and retrieve previous analyses using PostgreSQL.
- **PDF Reports:** Generate investigation reports for documentation.
- **REST API:** Use FastAPI endpoints to connect the dashboard with backend services.

## 🧰 Technology Stack

- **Backend:** Python, FastAPI
- **Database:** PostgreSQL
- **Threat Intelligence:** VirusTotal API, AbuseIPDB API
- **Security Tools:** Nmap
- **Additional Components:** WHOIS lookup, GeoIP, CVE lookup, risk engine, PDF reporting

## 🏗️ Project Architecture

The project follows a modular architecture:

- `backend/` — Backend application and API services
- `backend/routers/` — API routes for analysis, threat intelligence, scanning, reporting, and dashboard functionality
- `backend/` service modules — Threat intelligence integrations, scanning, risk assessment, and report generation

*The exact directory names may vary depending on the repository structure.*

## ⚙️ Installation and Setup

### Prerequisites

Install the following before starting:

- Python 3.10 or later (use the version supported by your dependencies)
- PostgreSQL
- Nmap
- Git
- API keys for the threat intelligence services you want to use

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd AI-Security-Copilot
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows:

```powershell
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

If the repository contains `requirements.txt`, run:

```bash
pip install -r requirements.txt
```

If dependencies are stored in a separate backend requirements file, run the command from the appropriate directory and use that file instead.

### 4. Configure environment variables

Create a `.env` file in the directory expected by the backend application.

Example configuration:

```env
DATABASE_URL=postgresql://USERNAME:PASSWORD@localhost:5432/ai_security_copilot
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

Replace the example values with your own configuration. Add other environment variables only if they are required by your application.

**Important:** Never commit your real API keys, passwords, or other secrets to GitHub. Add `.env` to `.gitignore`.

### 5. Set up PostgreSQL

Create a database named `ai_security_copilot` in PostgreSQL, then configure `DATABASE_URL` with your database username, password, host, port, and database name.

Run any database initialization or migration commands required by the project.

### 6. Install Nmap

On Kali Linux or Debian-based distributions:

```bash
sudo apt update
sudo apt install nmap
```

Verify the installation:

```bash
nmap --version
```

### 7. Start the backend

Navigate to the directory containing your FastAPI application.

For example, if the entry-point file is `main.py`:

```bash
uvicorn main:app --reload
```

If your application is inside a package or uses a different entry-point file, adjust the module path accordingly.

The API will typically be available at:

```text
http://127.0.0.1:8000
```

FastAPI interactive documentation:

```text
http://127.0.0.1:8000/docs
```

### 8. Start the frontend

If the repository includes a separate frontend, follow its setup instructions.

For a frontend based on Node.js, for example, install the dependencies using the package manager specified by its lockfile, then run its development script.

The frontend configuration should point to the backend API URL.

## 🔌 API Endpoints

The project includes API functionality for analysis, threat intelligence, scanning, reporting, and dashboard data.

| Endpoint | Purpose |
|---|---|
| `/api/analyze` | Analyze an indicator of compromise (IOC) |
| `/api/threat-intel` | Retrieve threat intelligence |
| `/api/history/` | Access investigation history |

Additional endpoints may be available for scanning, reports, and dashboard statistics. Refer to `/docs` for the actual registered routes.

## 🔍 Example Use Cases

- Investigating a suspicious IP address
- Checking a domain or URL against threat intelligence sources
- Reviewing risk scores for suspicious indicators
- Performing authorized network reconnaissance
- Maintaining a history of security investigations
- Generating reports for security analysis

## 🔐 Security and Responsible Use

- Use this application only on systems and networks you own or have explicit permission to assess.
- Keep API keys and database credentials private.
- Validate input before submitting indicators for analysis.
- Do not treat automated risk scores as a substitute for professional security investigation.
- Respect the terms and rate limits of external threat intelligence APIs.

## 🎯 Project Objective

The objective of AI Security Copilot is to simplify initial threat investigation by bringing multiple security intelligence sources and analysis capabilities into one place. The project demonstrates practical application of cybersecurity tools, API integration, backend development, database management, and risk assessment.
## 👩‍💻 Author
**Bhawana Kumawat**
B.Tech Computer Science Engineering — Cyber Security
GitHub: https://github.com/Bhawana-kumawat329

This project is intended for educational, research, and authorized defensive security purposes only.
