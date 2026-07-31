# PhishGuard Enterprise (v1.0) - Master Execution & Setup Guide

## 1. Overview
PhishGuard Enterprise is a production-grade, 16-engine email phishing analysis platform built from scratch. It inspects every inch of an email (headers, SPF/DKIM/DMARC live DNS records, domain reputation, sender trust, URLs, attachments, HTML structure, OCR/visual cues, content urgency, conversation threading, brand impersonation, and live threat intelligence feeds) to generate deterministic verdicts and forensic reports.

---

## 2. Project Architecture & Directory Structure
```text
src/
├── api/                  # FastAPI REST API endpoints
├── config/               # Centralized configuration (BaseSettings, .env)
├── database/             # Supabase PostgreSQL client
├── engines/              # 16 independent detection engines + input parser
│   ├── base_engine.py
│   ├── input_parser.py
│   ├── engine_1_header.py
│   ├── engine_2_auth.py          # SPF, DKIM, DMARC + Live DNS
│   ├── engine_3_domain.py
│   ├── engine_4_sender.py
│   ├── engine_5_url.py
│   ├── engine_6_attachment.py
│   ├── engine_7_html.py
│   ├── engine_8_visual.py
│   ├── engine_9_content.py
│   ├── engine_10_conversation.py
│   ├── engine_11_brand.py
│   ├── engine_12_threatintel.py  # VirusTotal, OpenPhish, AbuseIPDB, URLScan
│   ├── engine_13_behavior.py
│   ├── engine_14_correlation.py
│   ├── engine_15_scoring.py
│   └── engine_16_recommendation.py
├── integrations/         # Live API client integrations (Zero fake data)
├── logging/              # Structured JSON logging
├── models/               # Pydantic schemas
├── presentation/         # HTML5, Tailwind CSS, Vanilla JS frontend templates
├── repository/           # Repository pattern data access
├── reports/              # ReportLab PDF generator & JSON/CSV exporters
├── storage/              # Supabase storage manager
└── utils/                # Security sanitization & hashing
```

---

## 3. Step-by-Step Setup & Execution Instructions

### Step 3.1: Extract the Deliverable
Extract **`V1.zip`** into your local workspace directory and open it in **VS Code**.

### Step 3.2: Configure Environment Variables (`.env`)
Create a `.env` file in the root project directory:
```env
ENVIRONMENT=production
DEBUG=false

# Supabase Configuration (Optional - local JSON fallback is active if placeholders remain)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
SUPABASE_JWT_SECRET=your-supabase-jwt-secret

# Free Threat Intelligence API Keys (Register free accounts to enable live queries)
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
URLSCAN_API_KEY=your_urlscan_api_key
OPENPHISH_FEED_URL=https://openphish.com/feed.txt
```

### Step 3.3: Set Up Supabase Database (Optional for Cloud Persistence)
If you want cloud database persistence instead of local JSON repo fallback:
1. Log in to your Supabase Dashboard (`https://supabase.com`).
2. Create a new project and open the **SQL Editor**.
3. Run the following migration query to create the `analyses` table:
   ```sql
   create table analyses (
     id uuid default gen_random_uuid() primary key,
     analysis_id text unique not null,
     timestamp text not null,
     sha256 text not null,
     risk_score integer not null,
     severity text not null,
     verdict text not null,
     full_report jsonb not null,
     created_at timestamp with time zone default timezone('utc'::text, now()) not null
   );
   ```

### Step 3.4: Install Python Dependencies in VS Code
Open your VS Code terminal and run:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# macOS / Linux / Git Bash:
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3.5: Run the Server
Start the FastAPI server:
```bash
uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
```

### Step 3.6: Access the Application
- **Enterprise Web Dashboard:** Open `http://127.0.0.1:8000`
- **Interactive API Swagger Docs:** Open `http://127.0.0.1:8000/docs`

---

## 4. Production Docker Deployment
To run the platform containerized with Nginx:
```bash
docker-compose up --build -d
```
