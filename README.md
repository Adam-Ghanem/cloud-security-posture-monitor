# Cloud Security Posture Monitor

A defensive cloud security posture monitoring dashboard that helps visualize risky configurations, compliance gaps, and prioritized remediation actions.

> Built as a cybersecurity portfolio project by **Adam Ghanem**.

## What it does

- Displays a cloud posture score based on detected findings.
- Groups findings by severity: Critical, High, Medium, Low.
- Tracks risky areas such as identity, storage, network exposure, logging, and encryption.
- Provides simple remediation guidance for each finding.
- Includes a mock scanner so the project can run without connecting to real cloud accounts.

## Tech stack

- Frontend: React + Vite
- Styling: CSS
- Data: JSON sample findings
- Scanner prototype: Python

## Quick start

```bash
npm install
npm run dev
```

Then open the local URL shown by Vite.

## Run the mock scanner

```bash
python scanner/mock_scanner.py
```

The scanner prints sample posture findings in JSON format.

## Project structure

```text
cloud-security-posture-monitor/
├── data/
│   └── sample-findings.json
├── docs/
│   └── ARCHITECTURE.md
├── scanner/
│   └── mock_scanner.py
├── src/
│   ├── App.jsx
│   ├── main.jsx
│   └── styles.css
├── index.html
├── package.json
└── README.md
```

## Roadmap

- Add AWS/Azure/GCP read-only integrations.
- Add CIS benchmark mapping.
- Add PDF report export.
- Add authentication and team dashboards.
- Add historical posture trend charts.

## Security note

This project is for defensive monitoring and education. It does not perform exploitation or unauthorized access.
