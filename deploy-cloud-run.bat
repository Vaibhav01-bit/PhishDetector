@echo off
echo ============================================
echo  PhishDetector - Google Cloud Run Deploy
echo ============================================
echo.

REM Check if gcloud is installed
where gcloud >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: gcloud CLI is not installed.
    echo Download from: https://cloud.google.com/sdk/docs/install
    echo.
    pause
    exit /b 1
)

echo [1/5] Authenticating with Google Cloud...
gcloud auth login
if %errorlevel% neq 0 (
    echo ERROR: Authentication failed.
    pause
    exit /b 1
)

echo.
echo [2/5] Setting up project...
set /p PROJECT_ID="Enter your Google Cloud Project ID: "
gcloud config set project %PROJECT_ID%
if %errorlevel% neq 0 (
    echo ERROR: Failed to set project.
    pause
    exit /b 1
)

echo.
echo [3/5] Enabling required APIs...
gcloud services enable run.googleapis.com cloudbuild.googleapis.com containerregistry.googleapis.com
echo APIs enabled.

echo.
echo [4/5] Generating SECRET_KEY...
for /f "delims=" %%i in ('python -c "import secrets; print(secrets.token_hex(24))"') do set SECRET_KEY=%%i
echo Secret key generated.

echo.
echo [5/5] Building and deploying to Cloud Run...
echo This will take 5-10 minutes for the first build (Playwright + Chromium)...
echo.

echo --- Building Docker image via Cloud Build ---
gcloud builds submit --tag gcr.io/%PROJECT_ID%/phishdetector --region asia-south1
if %errorlevel% neq 0 (
    echo ERROR: Cloud Build failed.
    pause
    exit /b 1
)

echo.
echo --- Deploying image to Cloud Run ---
gcloud run deploy phishdetector ^
  --image gcr.io/%PROJECT_ID%/phishdetector ^
  --region asia-south1 ^
  --platform managed ^
  --allow-unauthenticated ^
  --memory 2Gi ^
  --timeout 300 ^
  --set-env-vars "SECRET_KEY=%SECRET_KEY%"

if %errorlevel% equ 0 (
    echo.
    echo ============================================
    echo  DEPLOYMENT SUCCESSFUL!
    echo ============================================
    echo.
    echo To get your URL, run:
    echo   gcloud run services describe phishdetector --region asia-south1 --format="value(status.url)"
    echo.
    echo To update after code changes:
    echo   gcloud builds submit --tag gcr.io/%%PROJECT_ID%%/phishdetector --region asia-south1
    echo   gcloud run deploy phishdetector --image gcr.io/%%PROJECT_ID%%/phishdetector --region asia-south1 --memory 2Gi --timeout 300
    echo.
) else (
    echo.
    echo ERROR: Deployment failed. Check the output above.
)

pause
