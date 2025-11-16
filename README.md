# 🧩 VersionDiff Sentinel

**VersionDiff Sentinel** is an advanced **software update integrity analyzer** that performs full static and differential malware analysis on software update packages (ZIPs).  
It simulates update checks, performs multi-phase static analysis, and generates AI-assisted forensic reports comparing software versions.

---

## 🚀 Features

- 🧠 **Automatic simulation** of update availability using sample ZIPs
- ⚙️ **Full static analysis**: entropy, IOCs, PE/ELF headers, digital signatures
- 📊 **Dark-themed HTML dashboard report**
- 🤖 **AI Forensic Summary** powered by Gemini 1.5 Pro
- 🔌 **FastAPI + WebSocket** real-time progress updates
- 🐳 **Fully Dockerized** for consistent deployment

---

---

## 🐳 Running with Docker

```bash
# 1️⃣ Clone repo
git clone https://github.com/abhinavbibek/versiondiff-sentinel.git
cd versiondiff-sentinel

# 2️⃣ Copy and configure environment
cp .env.example .env
nano .env

# 3️⃣ Build and run
docker compose up --build

# 4️⃣ Access the web UI
http://localhost:8000


| Endpoint                    | Method | Description                       |
| --------------------------- | ------ | --------------------------------- |
| `/api/check_update`         | GET    | Check simulation state            |
| `/api/apply_update`         | POST   | Apply update and trigger analysis |
| `/api/analyze`              | POST   | Manual analysis of two ZIPs       |
| `/api/ai_analyze`           | POST   | LLM forensic summary              |
| `/api/progress/{run_id}`    | GET    | Current analysis progress         |
| `/api/reports/{report_dir}` | GET    | View HTML or JSON report          |
| `/ws/progress/{run_id}`     | WS     | Real-time progress updates        |

AI Analysis Workflow

After both ZIPs analyzed → user clicks Perform AI Analysis

Server merges baseline_inventory.json + deep_analysis.json

Sends structured diff to Gemini via API

Receives Markdown forensic summary

Saves as ai_report.md in report directory



Each analysis produces:
reports/
└── v1_update/
    ├── baseline_inventory.json
    ├── deep_analysis.json
    └── full_report.html
└── v2_update/
    ├── baseline_inventory.json
    ├── deep_analysis.json
    └── full_report.html

AI reports:
ai_report.md


