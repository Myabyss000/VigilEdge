# 🌐 AI Web Interface Guide

## Quick Access

Your VigilEdge WAF now has **two ways** to view AI analysis:

### 1. 📊 Main Dashboard - AI Summary Widget
**URL:** http://localhost:5000/

The main dashboard now includes an **AI Analysis Summary** widget showing:
- **Total Scored:** Total events analyzed by AI
- **High Risk:** Events with AI score ≥ 0.7
- **Flagged:** Events requiring attention
- **Avg Score:** Average AI risk score

✨ **Real-time updates:** Stats refresh automatically via WebSocket

---

### 2. 🔬 Dedicated AI Analysis Page
**URL:** http://localhost:5000/ai-analysis

Full-featured AI analysis page with:
- **Complete statistics** for all AI-scored events
- **Score distribution** (Low/Medium/High risk breakdown)
- **Timeline chart** showing AI scores over time
- **Top flagged events** with detailed information
- **Real-time updates** via WebSocket

---

## How to Start

1. **Start the WAF:**
   ```powershell
   cd "c:\Users\Arghya\OneDrive\Desktop\python projects\vigiledge part 3\project-null-2.0\vigiledge-collage-project--main\VigilEdge"
   python waf/main.py
   ```

2. **Access the interfaces:**
   - Main Dashboard: http://localhost:5000/
   - AI Analysis Page: http://localhost:5000/ai-analysis

3. **Generate test traffic** (optional):
   ```powershell
   # In a new terminal
   python waf/tests/test_waf.py
   ```

---

## Features

### Real-Time Updates ✅
Both interfaces update automatically when:
- New events are scored by AI
- Risk levels change
- New threats are detected

### Data Displayed 📈
- **All AI-scored events** from your database (currently 187 events)
- **Heuristic scoring** (threat detection algorithms)
- **ML predictions** (when model is trained)
- **Risk levels:** Low (0-0.4), Medium (0.4-0.7), High (0.7-1.0)

### API Endpoints 🔌
The web interfaces use these endpoints:
- `/api/v1/ai-stats` - Summary statistics
- `/api/v1/ai-events` - Detailed event list
- WebSocket: `ws://localhost:5000/ws` - Real-time updates

---

## Viewing AI Data (Alternative Methods)

### Python Script (CLI)
```powershell
python check_ai_data.py
```
Shows last 10 AI-scored events in terminal.

### API Direct Access
```powershell
# PowerShell
Invoke-RestMethod http://localhost:5000/api/v1/ai-stats | ConvertTo-Json -Depth 10

# Or visit in browser:
# http://localhost:5000/api/v1/ai-stats
# http://localhost:5000/api/v1/ai-events
```

---

## Understanding AI Scores

### Score Ranges
- **0.0 - 0.4:** Low risk (green) ✅
- **0.4 - 0.7:** Medium risk (yellow) ⚠️
- **0.7 - 1.0:** High risk (red) 🚨

### Example Event
```json
{
  "timestamp": "2025-01-07T22:36:28",
  "source_ip": "192.168.1.100",
  "attack_type": "ddos",
  "action": "blocked",
  "ai_score": 0.845,
  "ai_confidence": 0.95,
  "note": "ddos:5.0 xss:0.0 sqli:0.0 path:0.0"
}
```

---

## Troubleshooting

### Dashboard not showing AI data?
1. Check if WAF is running: http://localhost:5000/
2. Verify events exist: `python check_ai_data.py`
3. Check browser console (F12) for errors

### No events showing?
- The database has 187 AI-scored events
- They should load automatically
- Try refreshing the page (F5)

### Real-time updates not working?
- Check WebSocket connection in browser console
- Ensure no firewall blocking port 5000
- Restart the WAF

---

## Next Steps

### Train ML Model (Optional)
To enable advanced ML predictions:

```powershell
python waf/scripts/train_alert_model.py
```

This creates:
- `waf/vigiledge/ml_models/alert_model.joblib`
- `waf/vigiledge/ml_models/alert_vectorizer.joblib`

After training, restart WAF to use ML scoring.

### Enable Auto-Blocking
Edit `waf/vigiledge/config.py`:
```python
ai_enabled = True
ai_auto_block_threshold = 0.85  # Block if AI score ≥ 0.85
```

---

## Summary

✅ **Main Dashboard** - Quick AI summary with 4 key metrics  
✅ **AI Analysis Page** - Complete analysis with charts and details  
✅ **Real-time updates** - Both interfaces update automatically  
✅ **187 events** - Already analyzed and ready to view  
✅ **Python CLI tool** - Alternative command-line viewer  

**Start viewing now:**
1. Run: `python waf/main.py`
2. Visit: http://localhost:5000/

🎉 Your AI features are ready to use!
