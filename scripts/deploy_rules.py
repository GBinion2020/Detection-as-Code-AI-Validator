import os
import requests
import json
import glob
import yaml
import sys
from datetime import date, datetime

KIBANA_URL = os.getenv("KIBANA_URL")
KIBANA_API_KEY = os.getenv("KIBANA_API_KEY")

if not KIBANA_URL or not KIBANA_API_KEY:
    print("Error: KIBANA_URL or KIBANA_API_KEY not set.")
    sys.exit(1)

headers = {
    "Authorization": f"ApiKey {KIBANA_API_KEY}",
    "kbn-xsrf": "true",
    "Content-Type": "application/json"
}

DETECTION_PATH = "detections/**/*.yml"

for rule_file in glob.glob(DETECTION_PATH, recursive=True):   #finds all detection rules
    with open(rule_file, "r") as f:
        rule = yaml.safe_load(f)

    # Try PUT (update) first
    response = requests.put(
        f"{KIBANA_URL}/api/detection_engine/rules",
        headers=headers,
        json=rule,
        verify=False
    )

    if response.status_code in (200, 201):
        print(f"Successfully updated: {rule_file}")
    else:
        # Fallback to POST (create) if PUT fails
        print(f"PUT failed for {rule_file} (Status: {response.status_code}), trying POST...")
        response = requests.post(
            f"{KIBANA_URL}/api/detection_engine/rules",
            headers=headers,
            json=rule,
            verify=False
        )
        
        if response.status_code in (200, 201):
            print(f"Successfully created: {rule_file}")
        else:
            print(f"\nFailed to deploy rule: {rule_file}")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
            sys.exit(1)