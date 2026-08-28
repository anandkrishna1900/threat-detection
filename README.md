# Hybrid Cybersecurity Threat Detection Platform

> An explainable hybrid cybersecurity threat detection platform that combines deterministic detection, behavioral analytics, unsupervised anomaly detection, and event correlation to identify and prioritize suspicious activity.

[![CI](https://github.com/your-username/threat-detection-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/threat-detection-platform/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Architecture

```
                    DATA SOURCES
                         |
        +----------------+----------------+
        |                |                |
      CSV/JSON          Logs           PCAP-derived
        |                |                |
        +----------------+----------------+
                         |
                         v
                 INGESTION LAYER
                         |
                         v
                EVENT NORMALIZATION
                         |
                         v
                 FEATURE EXTRACTION
                         |
           +-------------+-------------+
           |             |             |
           v             v             v
        RULES        ML ANOMALY    BEHAVIOR
        ENGINE         ENGINE       ENGINE
           |             |             |
           +-------------+-------------+
                         |
                         v
                  CORRELATION ENGINE
                         |
                         v
                    RISK ENGINE
                         |
                         v
               THREAT CLASSIFICATION
                         |
                         v
               ATT&CK TECHNIQUE MAP
                         |
                         v
                  INCIDENT ENGINE
                         |
               +---------+---------+
               |                   |
               v                   v
             REST API          DATABASE
               |                   |
               +---------+---------+
                         |
                         v
                     DASHBOARD
```

---

## Quick Start

### 1. Prerequisites

- Python 3.11 or later
- pip

### 2. Clone and Set Up

```bash
git clone https://github.com/your-username/threat-detection-platform.git
cd threat-detection-platform

# Create virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure

```bash
cp .env.example .env
# Edit .env as needed (defaults work for development)
```

### 4. Verify Setup

```bash
python main.py version
python main.py status
```

### 5. Run Tests

```bash
pytest tests/ -v
```

---

## Example Alert (Target Output — Phase 8)

```
Threat: Possible Credential Attack
Risk: 87/100        Severity: HIGH

Evidence:
  - 42 failed login attempts in 90 seconds
  - 5 usernames targeted (multi-account attack pattern)
  - Activity was 6.8x above this IP's baseline
  - Successful authentication occurred after failures

Detection sources:
  - Rule: BRUTE_FORCE_001 (Excessive Failed Logins)
  - Rule: BRUTE_FORCE_003 (Success After Repeated Failures)
  - Behavioral anomaly: login_frequency +6.8σ above baseline
  - ML anomaly: Isolation Forest score -0.41

Potential ATT&CK techniques:
  - T1110 (Brute Force) — Credential Access
  - T1078 (Valid Accounts) — possible, if authentication succeeded

Confidence: HIGH  |  Note: This is a suspected, not confirmed, attack.
```

---

## Phase Status

| Phase | Name | Status |
|-------|------|--------|
| 0 | Project Foundation | ✅ **Complete** |
| 1 | Data Ingestion | ✅ **Complete** |
| 2 | Event Normalization | ✅ **Complete** |
| 3 | Feature Engineering | ✅ **Complete** |
| 4 | Rule-Based Detection | 🔲 Not started |
| 5 | Behavioral Baselines | 🔲 Not started |
| 6 | ML Anomaly Detection | 🔲 Not started |
| 7 | Hybrid Risk Scoring | 🔲 Not started |
| 8 | Explainable Alerts | 🔲 Not started |
| — | **CORE CHECKPOINT** | — |
| 9 | Event Correlation | 🔲 Not started |
| 10 | Attack Chain Detection | 🔲 Not started |
| 11 | MITRE ATT&CK Mapping | 🔲 Not started |
| 12 | Risk Scoring Engine | 🔲 Not started |
| 13 | Database | 🔲 Not started |
| 14 | REST API | 🔲 Not started |
| 15 | Dashboard | 🔲 Not started |

---

## Detection Methodology

This platform uses **four complementary detection approaches**:

1. **Rule-based detection** — Deterministic rules with configurable thresholds (e.g., brute force: >10 failed logins in 60s from same IP). High precision, low recall on novel attacks.

2. **Behavioral baselines** — Per-entity (IP/user/host) statistical profiles. Anomalies flagged via z-score deviation. Surfaces novel deviations not covered by rules.

3. **ML anomaly detection (Isolation Forest)** — Unsupervised; trained on normal baseline data. Produces an anomaly score independent of rules. An ML anomaly score is **not** proof of malicious activity — it is one signal among several.

4. **Event correlation** — Groups related events across time into incidents. Transforms weak individual signals into coherent attack narratives.

All four signals are combined into a transparent **hybrid risk score** with documented, configurable weights. Every alert includes the specific evidence that triggered it — not just a conclusion.

---

## Dataset Disclaimer

> **Important**: All development and testing uses public benchmark datasets, synthetic data, and systems owned by the developer. No unauthorized scanning, traffic generation, or exploitation is performed. Real credentials, victim data, and sensitive logs are never included in this repository.
>
> Public datasets used (CIC-IDS2017, UNSW-NB15) have known limitations documented in `docs/evaluation.md`. Reported metrics apply only to those datasets under the conditions described — they do not represent real-world generalization performance.

---

## Evaluation Results

*Will be populated after Phase 6 (ML) and Phase 8 (Explainable Alerts) are complete.*

---

## Limitations

- Phase 0 only: no detection logic is implemented yet
- Dataset-specific metrics (to be added) will not generalize to arbitrary production traffic
- Risk score weights are heuristically chosen; empirical calibration is documented as it occurs

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
