# VigilEdge AI Chatbot Setup Guide

## 🤖 Your AI Security Assistant is Ready!

The chatbot has been integrated into your AI Analysis page with a beautiful floating interface.

## Setup LM Studio (5 Minutes)

### Step 1: Start LM Studio
1. Open **LM Studio** application
2. Make sure **Phi-3** model is downloaded

### Step 2: Start Local Server
1. Click on the **"Local Server"** tab (or **"Developer"** tab in older versions)
2. Select your **Phi-3** model from the dropdown
3. Click **"Start Server"**
4. Verify it shows: `Server running on http://localhost:1234`

### Step 3: Test the Chatbot
1. Start your WAF: `python waf/main.py`
2. Open http://127.0.0.1:5000/ai-analysis
3. Click the **floating chat button** (bottom right corner 💬)
4. Try these test queries:
   - "Show me recent attacks"
   - "What is SQL injection?"
   - "Analyze today's threats"
   - "How does the AI scoring work?"

## Features

✅ **Security Analysis** - Ask about attacks, threats, and firewall stats
✅ **Educational** - Learn about XSS, SQL injection, CSRF, etc.
✅ **Real-time Data** - Queries your actual security event database
✅ **Context-Aware** - Remembers conversation history
✅ **Beautiful UI** - Cyber-themed with animations and glow effects

## Troubleshooting

### "Cannot connect to LM Studio" Error
- Ensure LM Studio is running
- Check that the server is on port **1234**
- Load a model and click "Start Server"

### Slow Responses
- Normal for local LLMs (3-10 seconds)
- Phi-3 is optimized for speed
- Larger models (7B+) will be slower but more capable

### Chat Not Appearing
- Clear browser cache (Ctrl+Shift+R)
- Check browser console for errors (F12)

## For Hackathon Demo

### Impressive Questions to Ask:
1. "What threats have you detected in the last 24 hours?"
2. "Explain how your AI scoring system works"
3. "What's the difference between XSS and SQL injection?"
4. "Analyze the security posture of this system"
5. "What recommendations do you have to improve security?"

### Demo Flow:
1. Show the beautiful animated dashboard
2. Click chat button → "Hello! What can you do?"
3. Send attack from browser (SQL injection)
4. Ask: "What just happened? Analyze that attack"
5. Ask: "How did the AI detect it?"
6. Show judges the real-time statistics in responses

## Technical Details

- **Backend**: FastAPI endpoint at `/api/v1/chat`
- **Frontend**: Pure JavaScript, no framework needed
- **LLM API**: OpenAI-compatible (works with any OpenAI-compatible server)
- **Database**: Queries SQLite for real security event data
- **Context**: Includes recent attack statistics in every request

## Customization

Want to change the LM Studio URL? Edit `waf/main.py` line:
```python
lm_studio_url = "http://localhost:1234/v1/chat/completions"
```

Want different models? Any model works - just load it in LM Studio!

---

**🎉 You now have a fully functional AI Security Assistant chatbot!**

Impress those hackathon judges! 🏆
