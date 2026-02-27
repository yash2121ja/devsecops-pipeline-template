# 🔐 DevSecOps Pipeline Template

[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)
![Trivy](https://img.shields.io/badge/Trivy-1904DA?style=flat-square&logo=aquasecurity&logoColor=white)
![Semgrep](https://img.shields.io/badge/Semgrep-20C997?style=flat-square)
![Gitleaks](https://img.shields.io/badge/Gitleaks-FF4757?style=flat-square)

> Production-ready GitHub Actions workflows for DevSecOps — SAST, SCA, container scanning, secret detection, and IaC security checks. Drop into any repo and run in minutes.

---

## 🚀 Quick Start

Copy the workflow(s) you need into your repo's `.github/workflows/` directory:

```bash
# Clone this repo
git clone https://github.com/yash2121ja/devsecops-pipeline-template.git

# Copy the full pipeline into your project
cp -r devsecops-pipeline-template/.github/workflows/ your-project/.github/workflows/
cp -r devsecops-pipeline-template/configs/ your-project/configs/
```

---

## 🛡️ What's Included

| Workflow | File | What it does |
|----------|------|-------------|
| **Full Pipeline** | `devsecops-full.yml` | All checks in one — runs on every push/PR |
| **SAST** | `sast-scan.yml` | Semgrep static analysis (OWASP Top 10, language rules) |
| **Container Scan** | `container-scan.yml` | Trivy image scanning — fails on CRITICAL/HIGH |
| **Secret Detection** | `secret-scan.yml` | Gitleaks full-history secret scan |

---

## 🔍 Security Stages

```
Push / PR
    │
    ├─► 🔑 Secret Detection     ← Gitleaks — scans full git history
    │
    ├─► 🔍 SAST                 ← Semgrep — OWASP Top 10, Python, JS, TS, Docker
    │
    ├─► 📦 SCA (Dependencies)   ← Trivy filesystem scan — CVEs in packages
    │
    ├─► 🐳 Container Scan       ← Trivy image scan — OS + library CVEs
    │
    ├─► ☁️  IaC Scan             ← Trivy config scan — Terraform, K8s, Dockerfile
    │
    └─► 📊 Summary Report       ← Step summary in GitHub Actions UI
```

All findings upload to **GitHub Security → Code Scanning Alerts** as SARIF.

---

## ⚙️ Configuration

### Semgrep (`configs/semgrep.yml`)
Custom rules for hardcoded secrets, SQL injection, dangerous functions, and debug flags. Uses Semgrep's rule packs:
- `p/owasp-top-ten`
- `p/python` / `p/javascript` / `p/typescript`
- `p/secrets`
- `p/docker`

### Trivy (`configs/trivy.yaml`)
Scans for:
- OS and library CVEs
- IaC misconfigurations (Terraform, K8s, Dockerfile)
- Secrets embedded in code
- License compliance (blocks AGPL, GPL)

### Gitleaks (`configs/gitleaks.toml`)
Extends default rules with:
- Custom allowlists (test files, template vars)
- Custom internal token pattern detection

---

## 🔧 Optional Secrets

Set these in your repo **Settings → Secrets → Actions**:

| Secret | Used by | Required? |
|--------|---------|-----------|
| `SEMGREP_APP_TOKEN` | Semgrep cloud dashboard | Optional |
| `GITLEAKS_LICENSE` | Gitleaks org features | Optional |
| `SNYK_TOKEN` | Snyk SCA (if added) | Optional |

> Without these secrets the scans still run — they just won't push to cloud dashboards.

---

## 📋 Parse Scan Results Locally

```bash
# Run Trivy and save JSON
trivy fs . --format json --output trivy.json

# Parse and display summary
python scripts/parse_results.py --input trivy.json

# Fail CI if CRITICAL found
python scripts/parse_results.py --input trivy.json --fail-on CRITICAL
```

---

## 📊 GitHub Security Dashboard

After the pipeline runs, all findings appear in:
```
Your Repo → Security → Code Scanning Alerts
```

Filterable by severity, rule, file, and branch.

---

## 🗂️ Repository Structure

```
devsecops-pipeline-template/
├── .github/
│   └── workflows/
│       ├── devsecops-full.yml      # Full pipeline (all stages)
│       ├── sast-scan.yml           # SAST only — Semgrep
│       ├── container-scan.yml      # Container scan — Trivy
│       └── secret-scan.yml         # Secret detection — Gitleaks
├── configs/
│   ├── semgrep.yml                 # Semgrep custom rules
│   ├── trivy.yaml                  # Trivy configuration
│   └── gitleaks.toml               # Gitleaks rules + allowlist
├── scripts/
│   └── parse_results.py            # CLI tool to parse Trivy JSON output
└── README.md
```

---

## 📜 License

MIT — free to use, fork, and integrate into your own pipelines.

---

<div align="center">

Built by [yash2121ja](https://github.com/yash2121ja) · DevSecOps · Security Engineering

</div>
