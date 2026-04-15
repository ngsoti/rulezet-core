from flask import json
import requests


def convert_misp_to_stix(misp_object: json) -> dict | None:
    """Converts a MISP object to STIX via the cti-transmute.org API."""
    print("Converting MISP object to STIX...")
    try:
        response = requests.post(
            "https://cti-transmute.org/api/convert/misp_to_stix",
            json=misp_object,
            headers={"Content-Type": "application/json"},
            timeout=3
        )
        response.raise_for_status()

        return response.json()
    except requests.RequestException as e:
        print(f"Error converting MISP object to STIX: {e}")
        return None
    

