import requests
import os

# script to take all the differents licenses in the github repo to stock them in a txt file.

API_URL = "https://api.github.com/repos/spdx/license-list-XML/contents/src"
OUTPUT_FILE = "app/rule/import_licenses/licenses.txt"

def fetch_and_save_licenses():
    # Delete existing file if it exists
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)
        print(f"Old '{OUTPUT_FILE}' file deleted.")

    # Fetch license XML files from GitHub
    response = requests.get(API_URL)
    if response.status_code == 200:
        data = response.json()
        license_names = []

        for file in data:
            if file["name"].endswith(".xml"):
                license_names.append(file["name"].replace(".xml", ""))

        # Save the license names to a file
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for name in sorted(license_names):
                f.write(name + "\n")

        print(f"{len(license_names)} licenses saved to '{OUTPUT_FILE}'.")
    else:
        print(f"Error {response.status_code} while fetching licenses.")
