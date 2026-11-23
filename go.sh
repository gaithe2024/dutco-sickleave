#!/bin/bash
# DUTCO SICKLEAVE SYSTEM - one-time backend setup (run in Google Cloud Shell)
set -e
P=dutco-sickleave
gcloud config set project $P >/dev/null 2>&1
echo "== 1/5 Downloading code =="
cd ~ && rm -rf dutco && git clone -q https://github.com/gaithe2024/dutco-sickleave.git dutco
cd ~/dutco/backend/functions && npm install --no-fund --no-audit --silent && cd ..
echo "== 2/5 Enabling Google services (1-2 min) =="
gcloud services enable cloudfunctions.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com run.googleapis.com secretmanager.googleapis.com cloudscheduler.googleapis.com eventarc.googleapis.com pubsub.googleapis.com firebasestorage.googleapis.com --project $P
echo ""
echo "=================================================================="
echo "== 3/5 PASTE YOUR CLAUDE API KEY BELOW (it stays hidden), then press Enter =="
echo "=================================================================="
firebase functions:secrets:set ANTHROPIC_API_KEY --project $P
echo "== 4/5 Deploying (3-5 min) =="
for i in 1 2 3; do
  if firebase deploy --only functions,firestore:rules,storage --project $P --force; then OK=1; break; fi
  echo "Retrying in 60s ($i/3)..."; sleep 60
done
[ "$OK" = "1" ] || { echo "DEPLOY_FAILED"; exit 1; }
echo "== 5/5 Cleanup policy =="
firebase functions:artifacts:setpolicy --days 1 --force --location europe-west1 --project $P || true
echo "DUTCO_DEPLOY_DONE"
