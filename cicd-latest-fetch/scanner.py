#!/usr/bin/env python3
import requests
from models import ScanConfig
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = "apisec-cicd-latest-fetch/0.1.0"
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60


class Scanner:

    def __init__(self, scan_config: ScanConfig):
        self.scan_config = scan_config
        self.session = self._build_session(scan_config.access_token)

    @staticmethod
    def _build_session(access_token: str) -> requests.Session:
        s = requests.Session()
        retry = Retry(
            total=5,
            connect=3,
            read=3,
            backoff_factor=2,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.headers.update({
            "Authorization": f"Bearer {access_token}",
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        return s

    def _request(self, method: str, url: str, **kw) -> requests.Response:
        kw.setdefault("timeout", (CONNECT_TIMEOUT, READ_TIMEOUT))
        return self.session.request(method, url, **kw)

    def get_detections(self):
        """Fetch every detection currently on the configured instance.

        Single GET — the API returns the full envelope (no nextToken). Each
        detection record carries its own `status` (ACTIVE / DISMISSED /
        RISK_ACCEPTED / RESOLVED) and `testResult.cvssScore`, which the gate
        in main.py filters and counts.
        """
        url = (
            f"{self.scan_config.apisec_base_url}/v1/applications/"
            f"{self.scan_config.application_id}/instances/"
            f"{self.scan_config.instance_id}/detections"
        )
        params = {"include": "metadata", "slim": "true"}
        return self._request("GET", url, params=params)
