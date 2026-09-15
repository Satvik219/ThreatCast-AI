# ThreatCast AI

### AI-Powered Early Warning for Network Threats

ThreatCast is an explainable cybersecurity intelligence platform that predicts whether a network state is likely to transition into an attack condition within a future warning horizon.

The production system uses a temporal LSTM trained on the CTU13 botnet dataset. Network traffic is converted into 30-second network states, represented using 12 engineered temporal features, and evaluated using a 5-state temporal window.

ThreatCast combines:

- Temporal deep learning
- Early-warning prediction
- SHAP-based explainability
- MITRE ATT&CK-oriented threat interpretation
- Neo4j graph-based data storage
- FastAPI backend services
- React cybersecurity dashboard
- Packet-level graph research
- GraphSAGE-style representation learning
- Temporal Transformer-based latent forecasting

---

## 1. System Overview

ThreatCast is designed around a simple production principle:

> **Observe network behavior → model temporal evolution → predict early warning → explain the prediction → present actionable intelligence.**

The production inference pipeline is:

```text
CTU13 Network Flows
        ↓
30-Second Network-State Aggregation
        ↓
12 Engineered Features
        ↓
5 × 30-Second Temporal Window
        ↓
CTU13 LSTM
        ↓
Early-Warning Probability
        ↓
8% Decision Threshold
        ↓
Normal / Early Warning
        ↓
SHAP Explanation
        ↓
FastAPI
        ↓
Neo4j
        ↓
React Dashboard
```

## Quickstart

ThreatCast-AI runs fully offline, no external API calls. Python packages and
container images are downloaded during the first installation/build; model
inference itself stays on the local machine.

### Path A — zero-service demo (literal problem-statement path)

Python 3.11 is recommended. From the repository root:

```bash
pip install -r requirements.txt && streamlit run demo_app.py
```

Open <http://localhost:8501>, upload a CSV or PCAP, and run the analysis. The
app imports the existing inference, rollout, MITRE mapping, and live SHAP code
directly; FastAPI and Neo4j are not started.

Required environment variables: **none**.

### Path B — full React + FastAPI + Neo4j stack

With Docker Desktop (or Docker Engine with Compose) running:

```bash
docker compose up
```

Open the React dashboard at <http://localhost:5173>. FastAPI is available at
<http://localhost:8000/docs> and Neo4j Browser at <http://localhost:7474>.
Compose waits for Neo4j and FastAPI health checks and initializes the local
demo graph automatically.

Required environment variables: **none**. `docker-compose.yml` supplies the
container-local `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`,
`NEO4J_DATABASE`, `HOST`, `PORT`, `ENVIRONMENT`, `CORS_ALLOWED_ORIGINS`, and
`VITE_API_URL` values.

### Optional backend storage controls

These are optional and are not needed by either quickstart path:

- `THREATCAST_NO_NEO4J=1` forces the in-memory graph store.
- `THREATCAST_MEMORY_STORE_JSON=/path/to/seed.json` seeds that store from JSON.
- When running FastAPI outside Compose, set `NEO4J_URI`, `NEO4J_USERNAME`,
  `NEO4J_PASSWORD`, and optionally `NEO4J_DATABASE` to use Neo4j. If connection
  or authentication fails, the backend automatically falls back to memory.
