from pymisp import PyMISP

# MISP_URL = "https://misp.yourdomain.com"
# MISP_KEY = "YOUR_API_KEY"
MISP_URL = "https://misp.circl.com"
MISP_KEY = "circl"
MISP_VERIFYCERT = False  


def test_misp_connection():
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT, 'json')

        events = misp.search(controller="events", limit=3)

        if "response" in events and events["response"]:
            for e in events["response"]:
                print(f"[{e['Event']['id']}] {e['Event']['info']}")
            return True
        else:
            print("Connect but whitout event")
            return True

    except Exception as e:
        print(f"Error, no connection {e}")
        return False






# # Replace with your own MISP instance
# misp_url = "https://misp.circl.com"
# misp_key = "circl"

# connector = MISPConnector(misp_url, misp_key, verify_cert=False)
# connector.fetch_iocs(limit=5, ioc_type="ip-src")


# from pymisp import PyMISP
# from keys import misp_url, misp_key,misp_verifycert
# import argparse
# import os


# def init(url, key):
#     return PyMISP(url, key, misp_verifycert, 'json')


# def get_yara(m, event_id, out=None):
#     ok, rules = m.get_yara(event_id)
#     if not ok:
#         print(rules)
#     elif out is None:
#         print(rules)
#     else:
#         with open(out, 'w') as f:
#             f.write(rules)


# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description='Get yara rules from an event.')
#     parser.add_argument("-e", "--event", required=True, help="Event ID.")
#     parser.add_argument("-o", "--output", help="Output file")

#     args = parser.parse_args()

#     if args.output is not None and os.path.exists(args.output):
#         print('Output file already exists, abord.')
#         exit(0)

#     misp = init(misp_url, misp_key)

#     get_yara(misp, args.event, args.output)