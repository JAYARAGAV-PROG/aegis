# AEGIS Firewall — CC18 Complete Setup Guide
## Hackathon-ready in ~45 minutes

---

## What You're Building
- Windows agent monitors every app's real connections
- Backend checks every IP against AbuseIPDB (real threat intel)
- Gemini AI writes analysis for suspicious activity
- Dashboard shows everything live across all machines

---

## Step 1 — Get Your Free API Keys (10 min)

### AbuseIPDB (real IP threat intel)
1. Go to https://www.abuseipdb.com/register
2. Sign up free
3. Go to https://www.abuseipdb.com/account/api
4. Create API key — copy it

### Gemini API
1. Go to https://aistudio.google.com/app/apikey
2. Create API key — copy it

### Supabase (free database)
1. Go to https://supabase.com → New Project
2. Settings → API → copy Project URL and anon key

---

## Step 2 — Setup Database (5 min)

1. Open Supabase → SQL Editor
2. Paste the entire contents of `database/schema.sql`
3. Click Run
4. You should see 4 tables created: endpoints, connections, rules, alerts

---

## Step 3 — Run Backend (10 min)

```bash
cd backend

# Create .env file
cp .env.example .env
# Fill in your keys in .env

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

You should see: `Uvicorn running on http://0.0.0.0:8000`

---

## Step 4 — Run Frontend (5 min)

```bash
cd frontend

# Install
npm install

# Start
npm run dev
```

Open http://localhost:5173 → you see the AEGIS dashboard

---

## Step 5 — Run Agent on Your Machine (2 min)

```bash
cd agent

# Install
pip install psutil requests

# Run (as Administrator on Windows for firewall blocking)
python agent.py
```

Your machine appears in the dashboard immediately.

---

## Step 6 — Add Friends' Machines (5 min per friend)

**Option A — They run it themselves:**
1. Send them the `agent/` folder
2. Edit `agent.py` line 18 — change BACKEND_URL to your machine's IP
   ```python
   BACKEND_URL = "http://YOUR_IP_HERE:8000"
   ```
3. They run: `pip install psutil requests` then `python agent.py`

**Option B — You run it for them (their machine, physically):**
1. Plug in via hotspot or same WiFi
2. Run agent.py with your backend URL

---

## What Judges See (Demo Script)

### 1. Show live monitoring (30 sec)
"This is Rahul's laptop. AEGIS agent is running.
Every 5 seconds it captures all network connections.
Here — Chrome is connected to google.com, youtube.com.
Spotify is connected to these IPs. WhatsApp to these.
All scored by AbuseIPDB in real time."

### 2. Show a flagged connection (30 sec)
"This IP here — abuse score 87/100.
That means AbuseIPDB has real reports of this IP
being used for attacks. Our agent flagged it automatically."

### 3. Show Gemini analysis (30 sec)
"Gemini AI read all the connections for this process
and wrote this: [read the analysis]
This is not a template — Gemini wrote this fresh
from the actual connection data."

### 4. Block an IP live (30 sec)
"Watch. I click Block on this IP from the dashboard.
The backend sends the block order to the agent.
The agent runs: netsh advfirewall firewall add rule...
Now try to connect to that IP from Rahul's machine.
[try it — it's actually blocked]
That's a real Windows Firewall rule, not a simulation."

### 5. Show multiple endpoints (20 sec)
"We have 3 machines being monitored simultaneously.
Each one is sending real connection data.
From one dashboard we can see and control all of them."

---

## Troubleshooting

**Agent can't connect to backend:**
- Make sure backend is running on port 8000
- Check firewall allows port 8000
- Use your machine's actual IP, not localhost

**Firewall blocking doesn't work:**
- Run agent.py as Administrator
- Right-click → Run as Administrator

**AbuseIPDB returns 0 for all IPs:**
- Check your API key in .env
- Private IPs (192.168.x.x) always return 0 — that's correct

**Gemini analysis not showing:**
- Check GEMINI_API_KEY in .env
- Only triggers for abuse score > 50

---

## Real Data Flow (No Mock Anywhere)

```
Friend's laptop
  └── psutil reads REAL process connections
      └── agent.py POSTs to your backend
          └── backend checks REAL AbuseIPDB
              └── REAL Gemini analyzes patterns
                  └── REAL Supabase stores data
                      └── REAL WebSocket pushes to dashboard
                          └── YOU SEE IT LIVE
```
