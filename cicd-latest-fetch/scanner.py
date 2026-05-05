#!/usr/bin/env python3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from models import ScanConfig

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

    def get_application(self):
        """Fetch the application's metadata, including each instance's
        `latestScanStats` (which carries the most recent scan id)."""
        url = f"{self.scan_config.apisec_base_url}/v1/applications/{self.scan_config.application_id}"
        return self._request("GET", url)

    def scan(self, scan_id: str, next_token: str | None = None):
        url = f"{self.scan_config.apisec_base_url}/v1/applications/{self.scan_config.application_id}/instances/{self.scan_config.instance_id}/scans/{scan_id}"
        params = {"nextToken": next_token} if next_token else None
        return self._request("GET", url, params=params)
