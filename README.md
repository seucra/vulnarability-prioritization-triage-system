# Vulnerability Prioritization System

> A research-oriented project exploring machine learning assisted vulnerability prioritization using public cybersecurity datasets.

This project investigates how publicly available vulnerability intelligence can be combined to help prioritize security issues more effectively than relying on severity scores alone.

Originally developed as part of an academic project, it has gradually evolved into a broader engineering and research effort exploring vulnerability management, data processing, and applied cybersecurity.

Rather than attempting to replace existing security tools, the project focuses on understanding how different vulnerability signals can be aggregated, analyzed, and visualized to support better decision making.

---

# Motivation

Security teams often receive thousands of vulnerability reports while having limited resources to address them.

Not every critical CVE is actively exploited, and not every low-severity issue is safe to ignore.

The goal of this project is to explore practical approaches for prioritizing vulnerabilities using publicly available datasets, scoring systems, and machine learning techniques.

---

# Current Status

| Component                | Status                |
| ------------------------ | --------------------- |
| Data Collection          | Functional            |
| Data Processing Pipeline | Functional            |
| Dashboard                | Active Development    |
| Research                 | Ongoing               |
| Documentation            | In Progress           |

The project is currently an active engineering prototype and research exploration.

---

# Data Sources

The project currently explores information derived from public vulnerability datasets, including:

* CVE (Common Vulnerabilities and Exposures)
* CVSS
* EPSS
* CISA Known Exploited Vulnerabilities (KEV)
* Additional public security intelligence where appropriate

---

# Technology Stack

| Area             | Technologies                  |
| ---------------- | ----------------------------- |
| Backend          | Python                        |
| Data Processing  | Pandas, PyArrow               |
| Machine Learning | Scikit-learn                  |
| Visualization    | Streamlit                     |
| Storage          | Parquet, CSV                  |
| Research         | Public cybersecurity datasets |

---

# Repository Structure

```text
data/
models/
dashboard/
scripts/
research/
docs/
README.md
```

---

# Design Philosophy

This project emphasizes:

* Reproducible data processing
* Transparent scoring methods
* Practical experimentation
* Research-oriented development
* Explainable results

The objective is to better understand vulnerability prioritization rather than produce a commercial security platform.

---

# Roadmap

### Current

* Improve dashboard usability.
* Refine prioritization pipeline.
* Improve documentation.

### Next

* Evaluate additional prioritization features.
* Improve model evaluation.
* Expand research documentation.

### Future

* Continue exploring applied vulnerability intelligence.
* Compare different prioritization strategies.
* Investigate opportunities for further academic research.

---

# Repository Philosophy

This repository represents an ongoing learning effort at the intersection of cybersecurity, software engineering, and applied research.

As the project evolves, new datasets, models, and evaluation methods may be introduced while preserving reproducibility and clear documentation.

