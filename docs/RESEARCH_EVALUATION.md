# docs/RESEARCH_EVALUATION.md — Research Evaluation & Experimental Methodology

## 1. Research Problem & Hypothesis
Security Operations Centers (SOCs) suffer from severe alert fatigue and high investigation latencies caused by noisy, decoupled alerts.
- **Hypothesis**: A layered architecture combining:
  1. Deterministic rule-based detection,
  2. Temporal & entity-based alert deduplication,
  3. Graph-like multi-source event correlation into unified incidents, and
  4. Evidence-grounded local AI explanation,
  will reduce analyst triage overhead (measured in total alerts presented and triage duration) while maintaining high detection sensitivity (Recall >= 95% on realistic attack scenarios).

---

## 2. Experimental Comparative Tiers
The evaluation will compare four progressive configurations on identical benchmark datasets:
- **Baseline A**: Traditional Rule-Based Detection alone (raw alerts without deduplication or incident grouping).
- **Baseline B**: Rule-Based Detection with Fingerprint Deduplication.
- **Baseline C**: Rule-Based Detection with Deduplication and Multi-Entity Correlation into Incidents.
- **System D (Full Proposed System)**: Rules + Deduplication + Correlation + ML Anomaly Scoring + Evidence-Grounded AI Investigation Assistant.

---

## 3. Quantitative Evaluation Metrics
1. **Detection Performance**:
   - Precision = TP / (TP + FP)
   - Recall = TP / (TP + FN)
   - F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
   - False Positive Rate (FPR) = FP / (FP + TN)
2. **Alert Fatigue Reduction**:
   - Alert Reduction Ratio = (Raw Alerts - Consolidated Incidents) / Raw Alerts
   - Deduplication Ratio = (Total Alerts - Deduplicated Alerts) / Total Alerts
3. **Operational Performance**:
   - Ingestion Throughput (events/sec) under sustained load
   - Detection Latency (time from event ingestion to alert emission in milliseconds)
   - Search Query Latency across varying database sizes (10k, 100k, 1M events)
4. **AI Faithfulness & Hallucination Resistance**:
   - Evidence Citation Accuracy = (Correctly Cited Log IDs) / (Total Citations)
   - Hallucination Rate = (Unsupported Claims) / (Total Claims)

---

## 4. Test Datasets & Scenarios
- **Scenario 1: SSH Brute Force & Password Spraying (Kali -> Linux)**:
  - Controlled Hydra / Medusa dictionary attack against SSH.
- **Scenario 2: Windows Lateral Movement / Kerberoasting / Brute Force (Kali -> Windows Server)**:
  - Repeated Event 4625 followed by Event 4624 (Logon Type 3 or 10) and Event 4672.
- **Scenario 3: Normal Benign Activity Baseline**:
  - Regular administrative logons, scheduled tasks, transient network disconnects.
