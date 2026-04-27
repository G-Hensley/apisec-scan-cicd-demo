from dataclasses import dataclass
import os
import sys
from colors import Colors

"""Class representing scan parameters"""
@dataclass
class ScanConfig:
    application_id: str
    instance_id: str
    authentication_id: str
    access_token: str
    apisec_base_url: str
    fail_on_vulnerability_threshold: int
    fail_on_severity_exceeds_threshold: int
    print_summary: bool = True
    print_full: bool = False

    # Method to extract scan paramters from the Harness execution environment to power the plugin.
    @staticmethod
    def from_harness_execution_environment():
        application_id = os.getenv('INPUT_APPLICATION_ID')
        instance_id = os.getenv('INPUT_INSTANCE_ID')
        authentication_id = os.getenv('INPUT_AUTHENTICATION_ID')
        access_token = os.getenv('INPUT_ACCESS_TOKEN')
        apisec_base_url = ScanConfig._validate_base_url(
            os.getenv('INPUT_APISEC_BASE_URL', "https://api.apisecapps.com")
        )
        fail_on_vulnerability_threshold_str = os.getenv('INPUT_FAIL_ON_ERROR_THRESHOLD')
        fail_on_severity_threshold_str = os.getenv('INPUT_FAIL_ON_SEVERITY_THRESHOLD')
        print_summary = os.getenv('INPUT_PRINT_SUMMARY')
        print_full = os.getenv('INPUT_PRINT_FULL')

        if (not access_token) or (not application_id) or (not instance_id):
            print(f"{Colors.RED}The input settings `INPUT_APPLICATION_ID`, `INPUT_INSTANCE_ID` and `INPUT_ACCESS_TOKEN` are required{Colors.END}")
            sys.exit(1)

        return ScanConfig(application_id=application_id, 
                          instance_id=instance_id, 
                          authentication_id=authentication_id,
                          access_token=access_token,
                          apisec_base_url=apisec_base_url,
                          fail_on_vulnerability_threshold=ScanConfig._convert_to_integer(fail_on_vulnerability_threshold_str, 'INPUT_FAIL_ON_ERROR_THRESHOLD'),
                          fail_on_severity_exceeds_threshold=ScanConfig._convert_to_integer(fail_on_severity_threshold_str, 'INPUT_FAIL_ON_SEVERITY_THRESHOLD'),
                          print_summary=ScanConfig._convert_to_bool(print_summary),
                          print_full=ScanConfig._convert_to_bool(print_full))

    @staticmethod
    def _convert_to_bool(value):
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ('true', '1', 'yes', 'y', 'on'):
                return True
            if v in ('false', '0', 'no', 'n', 'off', ''):
                return False
            return True
        return bool(value)

    @staticmethod
    def _convert_to_integer(value, variable_name):
        if value is None or value == "":
            return sys.maxsize
        try:
            number = int(value)
            if number < 0:
                print(f"{Colors.YELLOW}The input variable {variable_name} must be a non-negative integer. Using Default.{Colors.END}")
                return sys.maxsize
            return number
        except ValueError:
            print(f"{Colors.YELLOW}The input variable {variable_name} needs to be integer. Using Default.{Colors.END}")
            return sys.maxsize

    @staticmethod
    def _validate_base_url(url):
        if not isinstance(url, str) or not url:
            print(f"{Colors.RED}INPUT_APISEC_BASE_URL is empty.{Colors.END}")
            sys.exit(1)
        url = url.rstrip('/')
        if not url.startswith('https://'):
            print(f"{Colors.RED}INPUT_APISEC_BASE_URL must use https:// (got: {url}). Refusing to send credentials over an insecure scheme.{Colors.END}")
            sys.exit(1)
        return url