# Nessus to Opensearch
Export Nessus scans results to Opensearch server to create dashboards, create custom alerts, and simplify vulnerability monitoring.

### Features
- Fetch scans since last timestamp in ```nessus_timestamp.txt```
- Send data to custom index define in ```.env``` with format ```index_name-YYY.MM.DD```
- Reverse DNS (if enable that can have impact on speed execution)
- Write logs in ```nessus_log.txt```

### Requirements
- Python and Pip (tested with Python 3.11+ and Pip 23+)
- Nessus scanner (tested with Nessus 10+)
- Opensearch Server and Dashboard (tested with Opensearch 2.x)

### Install Python libraries requirements
- ```pip install -r requirements.txt```

### Usage
This script is designed to be run automatically as a CRON task but can also be run manually.
- Clone repo
- Edit ```.env``` file
- Launch with ```python3 fetch_nessus_scans.py```
