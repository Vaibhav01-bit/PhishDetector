# Google Cloud Run Deployment Guide

## Quick Deploy

### Prerequisites

1. **Google Cloud Account** — Sign up at [cloud.google.com](https://cloud.google.com)
2. **gcloud CLI** — Install from [cloud.google.com/sdk](https://cloud.google.com/sdk/docs/install)
3. **Docker** (optional for local testing) — Install from [docker.com](https://www.docker.com/products/docker-desktop)

### Step 1: Setup Google Cloud Project

```bash
# Login to Google Cloud
gcloud auth login

# Create a new project (or use existing one)
gcloud projects create phish-detector --name="PhishDetector"

# Set the active project
gcloud config set project phish-detector

# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

### Step 2: Deploy to Cloud Run

```bash
# Deploy from source (Cloud Build handles Docker automatically)
gcloud run deploy phish-detector \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --cpu 1 \
  --timeout 300 \
  --min-instances 0 \
  --max-instances 10 \
  --set-env-vars "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(24))')"
```

**Important flags:**
- `--memory 2Gi` — Playwright + Chromium needs ~1.5GB
- `--timeout 300` — 5-minute timeout for sandbox scans
- `--min-instances 0` — Scales to zero (free when idle)
- `--allow-unauthenticated` — Public access

### Step 3: Set Environment Variables (Optional)

```bash
gcloud run services update phish-detector \
  --region us-central1 \
  --set-env-vars "TELEGRAM_BOT_TOKEN=your-token,TELEGRAM_CHAT_ID=your-chat-id"
```

### Step 4: Get Your URL

```bash
gcloud run services describe phish-detector --region us-central1 --format="value(status.url)"
```

---

## Local Docker Testing (Optional)

```bash
# Build the Docker image
docker build -t phish-detector .

# Run locally
docker run -p 8080:8080 phish-detector

# Access at http://localhost:8080
```

---

## Updating the Deployment

```bash
# Just run deploy again — it updates the existing service
gcloud run deploy phish-detector \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi \
  --timeout 300
```

---

## Cost Estimate (Monthly)

| Resource | Free Tier | Est. Cost |
|---|---|---|
| **Requests** | 2M free | ~$0 for low traffic |
| **vCPU-seconds** | 180k free | ~$0-5 for moderate usage |
| **Memory (2Gi)** | 360k GiB-seconds free | ~$0-10 |
| **Egress** | 1GB free | ~$0.12/GB after |
| **Container Registry** | 0.5GB free | ~$0.026/GB |

**Total**: ~$0-15/month for moderate usage

---

## Features Status on Cloud Run

| Feature | Status |
|---|---|
| 5-Layer Detection | ✅ Works |
| ML Model Prediction | ✅ Works |
| Forensic Analysis | ✅ Works |
| Email Scanning | ✅ Works |
| File Scanning | ✅ Works |
| QR Code Analysis (text) | ✅ Works |
| QR Code Analysis (image) | ✅ Works |
| **Sandbox Screenshot** | ✅ **Works** |
| Brand Impersonation Detection | ✅ Works |

---

## Troubleshooting

### "Service crashed" error
- Check logs: `gcloud run services describe phish-detector --region us-central1 --format="value(status.conditions)"`
- View logs: `gcloud run services logs read phish-detector --region us-central1 --limit=50`

### Sandbox timeout
- Increase timeout: `gcloud run services update phish-detector --timeout 600`
- Increase memory: `gcloud run services update phish-detector --memory 4Gi`

### Cold start takes too long
- Set min instances: `gcloud run services update phish-detector --min-instances 1`
- Costs ~$5-10/month extra but eliminates cold starts

### "No module named playwright"
- This shouldn't happen with Docker build — ensure `playwright` is in `requirements.txt`
- The Dockerfile runs `playwright install --with-deps chromium` automatically
