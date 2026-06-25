# Sentrix V7 — Deployment Guide

## Overview

Sentrix V7 has been completely re-architected from a multi-container microservice approach into a **single, unified FastAPI application** that runs all three engines (Threat, Prediction, Investigation) in a single process using an in-memory/SQLite event bus.

## Prerequisites

- Docker
- Docker Compose
- (Optional) `.env` file containing your API keys for connectors and AI integrations.

## Directory Structure

```text
Sentrix_V7/
├── docker-compose.yml
├── Dockerfile
├── main.py
├── requirements.txt
├── .env.example
├── validation/
└── sentrix_core/
    ├── threat_engine/
    ├── prediction_engine/
    ├── investigation_engine/
    ├── connector_framework/
    ├── rule_define_studio/
    ├── ai_layer/
    ├── config/
    └── event_bus/
```

## Setup & Deployment

1. **Clone the project & navigate to the directory:**
   ```bash
   cd Sentrix_V7
   ```

2. **Configure your Environment Variables:**
   Copy the example environment file and edit it to include your real API keys.
   ```bash
   cp .env.example .env
   ```

3. **Build the Docker image and Start the container:**
   ```bash
   docker-compose up -d --build
   ```

4. **Verify Deployment:**
   The single container `sentrix-core` will now be running on port `8000`. You can check the unified health endpoint:
   ```bash
   curl http://localhost:8000/api/v1/admin/health
   ```
   You should see all three engines reported as `"healthy"`.

## Run Validation Suite

A unified Python test script is provided to validate all functionalities, including event ingestion, forecast generation, incident investigation triggering, and rule CRUD.

```bash
python validation/test_sentrix_v7.py
```

All 10 tests should pass:
✅ ALL VALIDATION TESTS PASSED

## Data Persistence

All data is stored in the Docker Volume `sentrix-data` mounted at `/data/` inside the container. This includes:
- `/data/rule-repository/`
- `/data/custom-rules/active/`
- `/data/event_bus/`
- `/data/predictions/`
- `/data/investigations/`
- `/data/exports/`
- `/data/connectors/`
