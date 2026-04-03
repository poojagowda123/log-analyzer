# LogAnalyzer Pro - Complete Startup Guide

## 🚀 Quick Start (5-10 minutes)

### Step 1: Open PowerShell as Administrator
1. Press `Win + X`, select **Windows PowerShell (Admin)** or **Terminal (Admin)**
2. Navigate to the project root:
```powershell
cd "c:\Users\hp\OneDrive\Desktop\College Assignments\MINI PROJECT\LogAnalyzer1\LogAnalyzer"
```

### Step 2: Install Dependencies
Run once to install all required Python packages:
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Wait for all packages to install (may take 2-5 minutes).

---

## 📊 Running the Dashboard (Main UI)

### Option A: Quick Dashboard Only
If you just want to see the UI:

```powershell
cd "c:\Users\hp\OneDrive\Desktop\College Assignments\MINI PROJECT\LogAnalyzer1\LogAnalyzer"
python src/generate_demo_data.py
```

Wait for demo data to be created (shows checkmarks ✅).

Then run the dashboard:
```powershell
streamlit run dashboard/app.py
```

Opens browser at `http://localhost:8501` 🎉

---

## 🛡️ Full Security Daemon (Advanced)

### Step 1: Generate Demo Data
```powershell
cd "c:\Users\hp\OneDrive\Desktop\College Assignments\MINI PROJECT\LogAnalyzer1\LogAnalyzer"
python src/generate_demo_data.py
```

### Step 2: Start the Security Daemon (Background Process)
In a **new PowerShell Admin window**:
```powershell
cd "c:\Users\hp\OneDrive\Desktop\College Assignments\MINI PROJECT\LogAnalyzer1\LogAnalyzer\src"
python main_security_daemon.py --interval 60 --dry-run
```

- `--interval 60` = scan every 60 seconds (adjust as needed)
- `--dry-run` = no active blocking, just monitoring (safe mode)
- Remove `--dry-run` for active threat response (requires careful testing)

### Step 3: Open Dashboard in Another Window
In a **third PowerShell window** (no admin needed):
```powershell
cd "c:\Users\hp\OneDrive\Desktop\College Assignments\MINI PROJECT\LogAnalyzer1\LogAnalyzer"
streamlit run dashboard/app.py
```

Now you have:
- ✅ Daemon running (monitoring + parsing logs)
- ✅ Dashboard running (visualizing threats)

---

## 📋 Project Components Explained

| Component | What It Does | How to Run |
|-----------|------------|-----------|
| **Dashboard** | Web UI for analyzing logs & threats | `streamlit run dashboard/app.py` |
| **Security Daemon** | Real-time monitoring + threat response | `python src/main_security_daemon.py` |
| **Demo Data Generator** | Creates sample attack scenarios | `python src/generate_demo_data.py` |
| **Log Parsers** | Extracts logs from Windows & USB | Called by daemon automatically |
| **ML Detector** | Detects anomalies via ML models | Called by daemon automatically |
 
## 🔁 Orchestrator: Run All Parsers & Reports

A convenience script `run_all.py` runs the project's main `src/` scripts sequentially
and prints a combined summary. Run it from the project root (recommended):

```powershell
cd "c:\Users\hp\OneDrive\Desktop\College Assignments\MINI PROJECT\LogAnalyzer1\LogAnalyzer"
python run_all.py
```

If you are already inside the `src/` directory, run it with the parent path:

```powershell
python ..\run_all.py
```

The orchestrator captures each script's stdout/stderr and reports OK/FAIL/SKIPPED.
Use it for a quick end-to-end run during testing.


---

## 📂 File Structure

```
LogAnalyzer/
├── requirements.txt           ← Install these first
├── dashboard/
│   └── app.py               ← Run: streamlit run dashboard/app.py
├── src/
│   ├── main_security_daemon.py        ← Run: python main_security_daemon.py
│   ├── generate_demo_data.py          ← Run: python generate_demo_data.py
│   ├── parse_windows_logs.py          ← Called by daemon
│   ├── parse_usb_logs.py              ← Called by daemon
│   ├── ml_anomaly_detection.py        ← Called by daemon
│   └── [other modules]
└── Output/                   ← Daemon writes results here
    ├── ml_anomalies.csv
    ├── attack_identifications.csv
    ├── suspicious_events.csv
    └── [other output files]
```

---

## 🔧 Troubleshooting

### Issue: "No module named 'psutil'"
**Solution:** Run pip install again:
```powershell
pip install psutil pandas numpy plotly streamlit scikit-learn joblib pyvis
```

### Issue: "Cannot find path" or "File does not exist"
**Solution:** Make sure you're in the correct directory. Verify:
```powershell
cd "c:\Users\hp\OneDrive\Desktop\College Assumptions\MINI PROJECT\LogAnalyzer1\LogAnalyzer"
ls  # Should show: dashboard/, src/, Output/, requirements.txt, etc.
```

### Issue: Dashboard shows "DATA OFFLINE" or empty metrics
**Solution:** You haven't generated demo data yet. Run:
```powershell
python src/generate_demo_data.py
```
Then refresh the dashboard (Ctrl+R in browser or restart the app).

### Issue: "Permission Denied" or "Access Denied"
**Solution:** Run PowerShell as Administrator (right-click → Run as Administrator).

### Issue: Port 8501 already in use
**Solution:** Stop the old Streamlit process and run:
```powershell
streamlit run dashboard/app.py --server.port 8502
```

---

## 🎯 Typical Workflow

1. **Setup** (one-time):
   ```powershell
   pip install -r requirements.txt
   python src/generate_demo_data.py
   ```

2. **Daily Use**:
   ```powershell
   # Terminal 1: Security Daemon
   python src/main_security_daemon.py --interval 60 --dry-run
   
   # Terminal 2: Dashboard
   streamlit run dashboard/app.py
   ```

3. **View Results**:
   - Open browser → `http://localhost:8501`
   - Navigate using sidebar menu
   - Click "MAIN DASHBOARD" tabs to view alerts

---

## 📊 Dashboard Pages

- **MAIN DASHBOARD** → System events, threat metrics, alerts
- **USB SECURITY** → USB device scanning & threats
- **NLP ANALYSIS** → Semantic threat classification
- **USB FILE SCANNER** → Malware scanning on drives
- **Knowledge Graph** → Threat relationships
- **Visualizations** → Charts & patterns
- **ML Anomalies** → Machine learning detections
- **BERT Anomalies** → Deep learning threat analysis

---

## 🚨 Important Notes

⚠️ **Run as Administrator** for full functionality (especially daemon)  
⚠️ **--dry-run mode** recommended for first-time testing  
⚠️ **Check security_daemon.log** for errors: `Get-Content .\security_daemon.log -Wait`  
⚠️ **Output folder** should populate after daemon runs  

---

## ✅ Verification Checklist

- [ ] Python 3.8+ installed (`python --version`)
- [ ] All packages installed (`pip list | grep pandas`)
- [ ] Running as Administrator
- [ ] Output/ folder exists
- [ ] Demo data generated (`ls Output/` should show CSVs)
- [ ] Dashboard loads without errors
- [ ] Can navigate between pages
- [ ] Daemon runs without crashing

---

## 📞 Quick Commands Reference

| Task | Command |
|------|---------|
| Install deps | `pip install -r requirements.txt` |
| Generate demo | `python src/generate_demo_data.py` |
| Start daemon | `python src/main_security_daemon.py --interval 60 --dry-run` |
| Start dashboard | `streamlit run dashboard/app.py` |
| Check logs | `Get-Content .\security_daemon.log -Wait` |
| View output | `ls Output/` |
| Stop daemon | Ctrl+C in terminal |
| Stop dashboard | Ctrl+C in terminal |

---

**Happy monitoring! 🛡️**
