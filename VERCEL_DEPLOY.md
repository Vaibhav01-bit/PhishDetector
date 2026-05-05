# PhishDetector - Vercel Deployment Guide

## Quick Deploy

1. Push your code to a GitHub repository
2. Go to [vercel.com](https://vercel.com) and click **New Project**
3. Import your GitHub repo
4. Vercel will auto-detect the `vercel.json` config
5. Click **Deploy**

## Environment Variables (Set in Vercel Dashboard)

Go to **Settings > Environment Variables** and add:

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | **Yes** | Flask session secret (use a random 24+ char string) |
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot token for notifications |
| `TELEGRAM_CHAT_ID` | No | Telegram chat ID for notifications |
| `FLASK_ENV` | No | Set to `development` to enable debug mode |

**Generate a SECRET_KEY:**
```bash
python -c "import secrets; print(secrets.token_hex(24))"
```

## What Works on Vercel

- **5-Layer Security Analysis** (Blacklist, Domain, SSL, ML Model, Behavioral)
- **ML Model Prediction** (uses `src/ml/newmodel.pkl`)
- **Forensic Analysis** (redirects, WHOIS, IP resolution)
- **Email Scanning** (URL extraction + analysis)
- **File Scanning** (PDF, DOCX, XLSX analysis)
- **QR Code Text Analysis** (URL, UPI, WiFi, SMS detection)
- **Brand Impersonation Detection**
- **Fast + Progressive Scan** (AJAX polling)

## What Does NOT Work on Vercel

- **Sandbox / Screenshot Capture** — Requires Playwright + Chromium (150MB+) which exceeds serverless limits
- **QR Image Decoding** — Requires `pyzbar` which needs native `libzbar` C library

These features are automatically disabled when `VERCEL_DEPLOYMENT=true`.

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally (sandbox enabled for local dev)
python app.py

# Or with debug mode
set FLASK_ENV=development
python app.py
```

## Project Structure for Vercel

```
Phishing Website Detector/
├── api/
│   └── index.py          # Vercel serverless entry point
├── src/
│   ├── ml/
│   │   └── newmodel.pkl  # ML model (MUST be committed)
│   └── pipeline/
│       ├── brand_registry.json  # Brand detection rules
│       └── ...
├── templates/            # Jinja2 HTML templates
├── static/               # CSS, JS, images
├── vercel.json           # Vercel config
├── requirements.txt      # Python dependencies
├── .python-version       # Pin Python 3.12
└── app.py                # Flask application
```

## Important Notes

1. **ML Model File**: `src/ml/newmodel.pkl` must be committed to the repo (not in .gitignore)
2. **Blacklist**: `blacklist.txt` is optional — if missing, Layer 1 skips blacklist checks
3. **WHOIS Lookups**: May be slow or fail on some domains due to rate limiting
4. **Cold Starts**: First request after inactivity may take 10-30 seconds due to ML model loading
5. **Serverless Limits**: Each request has a 10-second timeout (Hobby) or 60-second (Pro) — long scans may timeout

## Troubleshooting

### "Module not found" error
- Ensure `api/index.py` exists and has the correct `sys.path` setup
- Check that all imports use relative paths from project root

### ML Model not loading
- Verify `src/ml/newmodel.pkl` exists in the deployed code
- Check Vercel function logs for pickle load errors

### Scan timeouts
- WHOIS lookups and Google search can be slow
- Consider adding timeouts to external calls in `src/feature.py`

### CORS issues
- CORS is configured for `/api/*` endpoints only
- If your frontend is on a different domain, update `app.py` line 30
