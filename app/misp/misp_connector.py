from pymisp import PyMISP
from typing import Optional, List, Dict


class MISPConnector:

    # MISP Configuration
    # MISP_URL = "http://localhost/"
    # MISP_KEY = "d3Q9gTq4NSgpRx93smsF54goQrURns8vfi9qf3xM"
    # MISP_VERIFYCERT = False

    # # # MISP Connector instance
    # # misp_client = MISPConnector(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    """
    A clean class to manage MISP connections and interactions.
    """
    def __init__(self, url: str, api_key: str, verify_cert: bool = False, output_format: str = 'json'):
        self.url = url
        self.api_key = api_key
        self.verify_cert = verify_cert
        self.output_format = output_format
        self.misp: Optional[PyMISP] = None

    def connect(self) -> bool:
        """Establish a connection to MISP."""
        try:
            self.misp = PyMISP(self.url, self.api_key, self.verify_cert, self.output_format)
            # Test connection by fetching some events
            events , success = self.get_events(limit=3)
            if events and success:
                for e in events:
                    print(f"[{e['Event']['id']}] {e['Event']['info']}")
            return True
        except Exception as e:
            return False

    def disconnect(self):
        """Clear the connection."""
        try:
            self.misp = None
            return True
        except Exception as e:
            return False

    def get_events(self, limit: int = 10) -> List[Dict]:
        """Fetch recent events from MISP."""
        if not self.misp:
            raise RuntimeError("MISP connection not established.")
        try:
            result = self.misp.search(controller="events", limit=limit)

            if isinstance(result, dict) and "response" in result:
                return result["response"] , True
            elif isinstance(result, list):
                return result , True
            else:
                return [] , True
        except Exception as e:
            print(f"[MISPConnector] Error fetching events: {e}")
            return [] , False


    def create_event(self, info: str, distribution: int = 0, threat_level_id: int = 4) -> Optional[Dict]:
        """Create a new MISP event."""
        if not self.misp:
            raise RuntimeError("MISP connection not established.")
        try:
            event = self.misp.add_event({
                "info": info,
                "distribution": distribution,
                "threat_level_id": threat_level_id
            })
            return event
        except Exception as e:
            print(f"[MISPConnector] Error creating event: {e}")
            return None
