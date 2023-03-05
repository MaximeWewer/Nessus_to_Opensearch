# Nessus to Opensearch
Export Nessus scans results to Opensearch server for create dashboards, create custom alerts, and simplify vulnerability monitoring.

### Requirements
- Python (tested with Python 3.11+)
- Nessus scanner (tested with Nessus 10+)
- Opensearch Server and Dashboard (tested with Opensearch 2.x)

### Install Python libraries requirements
- ```pip install -r requirements.txt```

### Usage
This script is designed to be run automatically as a CRON task but can also be run manually.
- Clone repo
- Edit ```.env``` file
- Launch with ```python3 fetch_nessus_scans.py```
