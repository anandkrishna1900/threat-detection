# Architecture

## Overview

The Hybrid Cybersecurity Threat Detection Platform is a modular,
pipeline-based system for ingesting security events, detecting anomalies
and suspicious patterns through multiple complementary approaches,
correlating events into incidents, and exposing results through an API
and dashboard.

## Design Principles

1. **Correctness before complexity** — each phase is tested before the next begins.
2. **Evidence before conclusions** — every alert includes the specific events and
   measurements that triggered it.
3. **Explainability before black-box predictions** — risk scores are broken into
   transparent components; ML scores are one signal, not the verdict.
4. **Modular architecture** — each layer has a single responsibility and a clean
   interface to the next.
5. **Reproducibility** — fixed seeds, documented splits, versioned artifacts.

## Component Descriptions

### Ingestion Layer (`src/ingestion/`)
Reads raw security event data from CSV, JSON, and JSON Lines sources.
Yields raw records without any detection logic — detection is never the
ingestion layer's responsibility.

**Interface:** `DataSource` → yields raw `dict` records → `Normalizer`

### Event Normalization (`src/normalization/`)
Maps heterogeneous field names to a canonical `SecurityEvent` schema.
Normalizes timestamps to UTC, IP representations, ports, protocols, and
categorical values. Preserves both original and normalized forms.

**Interface:** raw `dict` → `SecurityEvent` (Pydantic model)

### Feature Engineering (`src/features/`)
Derives cybersecurity-meaningful features from normalized events.
Includes network flow features, authentication features, host behavior
features, and temporal rolling-window features. Never leaks labels.

**Interface:** `SecurityEvent` stream → `FeatureVector`

### Rule-Based Detection Engine (`src/detection/rules/`)
Configurable, threshold-based detection rules loaded from
`configs/detection_rules.yaml`. Each rule produces a `RuleResult`
with `triggered`, `severity`, `evidence`, and `mitre` attributes.

**Interface:** `FeatureVector` → `RuleResult`

### Behavioral Baseline Engine (`src/detection/behavioral/`)
Maintains per-entity (IP/user/host) statistical profiles of normal
behavior. Computes z-score deviation for each observed event.
Outputs `BehaviorAnomaly` objects with `explanation` fields.

**Interface:** `FeatureVector` → `BehaviorAnomaly`

### ML Anomaly Detection Engine (`src/detection/ml/`)
Isolation Forest trained on clean baseline data. Produces an anomaly
score per event. Threshold calibrated on a held-out validation split.
One-Class SVM available as an optional comparison experiment.

**Interface:** `FeatureVector` → `MLResult`

### Correlation Engine (`src/correlation/`)
Groups related `SecurityEvent`s into `Incident` objects using time
proximity, shared entities (IP, user, host), and related services.
Correlation windows are configurable. Every correlation decision is
logged with the criteria that matched.

**Interface:** `Alert` stream → `Incident`

### Risk Engine (`src/scoring/`)
Combines Rule Score + Behavior Score + ML Score + Correlation Bonus
into a transparent 0–100 risk score. Weights are configurable via
`configs/risk_config.yaml`. Component breakdown is stored with every
alert and incident.

**Interface:** `RuleResult` + `BehaviorAnomaly` + `MLResult` → `RiskScore`

### Threat Classification (`src/classification/`)
Maps detection output to threat categories
(Brute Force, Port Scan, Data Exfiltration, Lateral Movement, etc.)
using deterministic classification logic, not LLM inference.

### ATT&CK Mapping (`src/attack_mapping/`)
Maps detections to MITRE ATT&CK technique IDs. Mapping is traceable
to specific detection logic — no speculative technique assignment.

### Incident Engine (`src/incidents/`)
Assembles correlated alerts into a full `Incident` with: timeline,
affected entities, risk score, confidence, ATT&CK techniques,
supporting evidence, and investigation notes.

### Storage (`src/storage/`)
SQLAlchemy ORM over SQLite (development) / PostgreSQL (production).
Stores all entities: `SecurityEvent`, `Detection`, `Alert`, `Incident`,
`Entity`, `BehaviorBaseline`, `ModelVersion`, `DetectionRule`,
`AttackTechnique`.

### REST API (`src/api/`)
FastAPI application exposing detection results.
Auto-generated OpenAPI docs at `/docs`.

### Dashboard (`src/dashboard/`)
Streamlit dashboard for visualizing alerts, incidents, risk scores,
and ATT&CK technique coverage.

## Data Flow

```
Raw input file
     │
     ▼
DataSource.read() → raw dict records
     │
     ▼
Normalizer.normalize() → SecurityEvent
     │
     ▼
FeatureExtractor.extract() → FeatureVector
     │
     ├──────────────────────────────────────┐
     ▼                                      │
RulesEngine.evaluate() → RuleResult        │
BehaviorEngine.score() → BehaviorAnomaly   │
MLEngine.score() → MLResult                │
     │                                      │
     ▼                                      │
RiskEngine.compute() → RiskScore ←─────────┘
     │
     ▼
ThreatClassifier.classify() → ThreatCategory
ATTACKMapper.map() → [TechniqueID]
     │
     ▼
ExplainableAlert (evidence + inference + confidence)
     │
     ▼
CorrelationEngine.correlate() → Incident
     │
     ├──────────────────────────┐
     ▼                          ▼
  Storage                  REST API
     │                          │
     └──────────┬───────────────┘
                ▼
           Dashboard
```

## Configuration

All tuneable parameters are externalised:
- `configs/detection_rules.yaml` — rule thresholds, windows, enabled state
- `configs/model_config.yaml` — ML algorithm parameters, preprocessing
- `configs/risk_config.yaml` — risk weights, severity thresholds
- `.env` — infrastructure (DB URL, API port, log level)

No detection threshold is hardcoded in source code where a config value
is practical.

## Phase Checkpoints

- **CORE (Phases 0–8)**: Foundation through Explainable Alerts.
  Must be fully tested and documented before EXTENDED work begins.
- **EXTENDED (Phases 9–15)**: Correlation through Dashboard.
  Must be stable before ADVANCED work begins.
- **ADVANCED (optional)**: Streaming, Docker/CI, ablation studies.
