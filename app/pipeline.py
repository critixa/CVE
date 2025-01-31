import requests
import json
import os
from datetime import datetime
from app.config import CVE_API_URL, LOG_FILE, CVE_ID_ATTRIBUTE, CVE_SOURCE_ATTRIBUTE, CVE_PUBLISHED_ATTRIBUTE, \
    CVE_LAST_MODIFIED_ATTRIBUTE, CVE_VUL_STATUS_ATTRIBUTE, CVE_METRICS_ATTRIBUTE, CVE_CONFIGURATIONS_ATTRIBUTE, \
    METRICS_CVSS_V3, METRICS_CVSS_V2, METRIC_DATA_TYPE, METRIC_DATA_SOURCE, METRIC_DATA_CVSS_DATA, \
    METRIC_DATA_BASE_SEVERITY, METRIC_DATA_EXPLOITABILITY_SCORE, METRIC_IMPACT_SCORE, METRIC_DATA_AC_INSUF_INFO, \
    METRIC_DATA_OBTAIN_ALL_PRIVILEGE, METRIC_DATA_USER_PRIVILEGE, METRIC_DATA_OBTAIN_OTHER_PRIVILEGE, \
    METRIC_DATA_USER_INTERACTION_REQUIRED, CVSS_DATA_VERSION, CVSS_DATA_VECTOR_STRING, CVSS_DATA_BASE_SCORE, \
    CVSS_DATA_ACCESS_VECTOR, CVSS_DATA_ACCESS_COMPLEXITY, CVSS_DATA_AUTHENTICATION, CVSS_DATA_CONFIDENTIALITY_IMPACT, \
    CVSS_DATA_INTEGRITY_IMPACT, CVSS_DATA_AVAILABILITY_IMPACT, CVE_CONFIGURATIONS_NODES_ATTRIBUTE, \
    CVE_CONFIGURATIONS_CPE_MATCH_ATTRIBUTE, CONFIGURATION_VULNERABLE, CONFIGURATION_CRITERIA, \
    CONFIGURATION_MATCH_CRITERIA_ID, RESPONSE_VULNERABILITIES_ATTRIBUTE, RESPONSE_CVE_ATTRIBUTE


def setup_log():
    """
    Ensure a new log file is created.
    If an existing log file is found, delete it first.
    """
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)  # Delete the existing log file
        print(f"Deleted existing log file: {LOG_FILE}")

    with open(LOG_FILE, "w") as f:
        f.write("Error Logs for CVE Data Pipeline\n")
        f.write("="*50 + "\n")
    print(f"Created new log file: {LOG_FILE}")


def log_error(error_id, cve_data, reason):
    """Log error details to a file."""
    with open(LOG_FILE, "a") as f:
        f.write(f"\n[ERROR_ID: {error_id}] {datetime.now()}\n")
        f.write(f"Reason: {reason}\n")
        f.write(f"CVE Data: {json.dumps(cve_data, indent=4)}\n")
        f.write("-" * 50 + "\n")


def fetch_cve_data():
    """Fetch CVE data from the external API."""
    response = requests.get(CVE_API_URL)
    if response.status_code == 200:
        return response.json()
    return None


def validate_cve(cve):
    """Ensure each CVE entry has required fields and valid data."""
    required_fields = [CVE_ID_ATTRIBUTE, CVE_SOURCE_ATTRIBUTE, CVE_PUBLISHED_ATTRIBUTE, CVE_LAST_MODIFIED_ATTRIBUTE, CVE_VUL_STATUS_ATTRIBUTE, CVE_METRICS_ATTRIBUTE, CVE_CONFIGURATIONS_ATTRIBUTE]

    # Validate Required Fields
    for field in required_fields:
        if not cve.get(field):
            log_error(cve.get(CVE_ID_ATTRIBUTE, "UNKNOWN_CVE"), cve, f"Missing required field: {field}")
            return False

    # Validate Metrics
    metrics = cve.get("metrics", {})
    if METRICS_CVSS_V2 in metrics and METRICS_CVSS_V3 in metrics:
        log_error(cve[CVE_ID_ATTRIBUTE], cve, "Both cvssMetricV2 and cvssMetricV3 exist. Invalid entry.")
        return False

    valid_metric_keys = {
        METRIC_DATA_SOURCE, METRIC_DATA_TYPE, METRIC_DATA_CVSS_DATA, METRIC_DATA_BASE_SEVERITY, METRIC_DATA_EXPLOITABILITY_SCORE, METRIC_IMPACT_SCORE,
        METRIC_DATA_AC_INSUF_INFO, METRIC_DATA_OBTAIN_ALL_PRIVILEGE, METRIC_DATA_USER_PRIVILEGE, METRIC_DATA_OBTAIN_OTHER_PRIVILEGE, METRIC_DATA_USER_INTERACTION_REQUIRED
    }

    cvss_version = METRICS_CVSS_V2 if METRICS_CVSS_V2 in metrics else METRICS_CVSS_V3 if METRICS_CVSS_V3 in metrics else None

    if not cvss_version:
        log_error(cve[CVE_ID_ATTRIBUTE], cve, "Missing CVSS version (cvssMetricV2 or cvssMetricV3).")
        return False

    cvss_metric = metrics[cvss_version][0]

    # Validate that all required metric keys exist
    missing_keys = valid_metric_keys - cvss_metric.keys()
    if missing_keys:
        log_error(cve[CVE_ID_ATTRIBUTE], cve, f"Missing required metric fields: {', '.join(missing_keys)}")
        return False

    # Validate cvssData
    required_cvss_keys = {CVSS_DATA_VERSION, CVSS_DATA_VECTOR_STRING, CVSS_DATA_BASE_SCORE, CVSS_DATA_ACCESS_VECTOR,
                          CVSS_DATA_ACCESS_COMPLEXITY, CVSS_DATA_AUTHENTICATION, CVSS_DATA_CONFIDENTIALITY_IMPACT,
                          CVSS_DATA_INTEGRITY_IMPACT, CVSS_DATA_AVAILABILITY_IMPACT}

    cvss_data = cvss_metric.get(METRIC_DATA_CVSS_DATA, {})
    missing_cvss_keys = required_cvss_keys - cvss_data.keys()

    if missing_cvss_keys:
        log_error(cve[CVE_ID_ATTRIBUTE], cve, f"Missing required cvssData fields: {', '.join(missing_cvss_keys)}")
        return False

    # Validate Configurations
    if not isinstance(cve[CVE_CONFIGURATIONS_ATTRIBUTE], list):
        log_error(cve[CVE_ID_ATTRIBUTE], cve, "Invalid configurations format: Expected a list.")
        return False

    for config in cve[CVE_CONFIGURATIONS_ATTRIBUTE]:
        if not isinstance(config.get(CVE_CONFIGURATIONS_NODES_ATTRIBUTE), list):
            log_error(cve[CVE_ID_ATTRIBUTE], cve, "Invalid configurations nodes format: Expected a list.")
            return False

        for node in config[CVE_CONFIGURATIONS_NODES_ATTRIBUTE]:
            if not isinstance(node.get(CVE_CONFIGURATIONS_CPE_MATCH_ATTRIBUTE), list):
                log_error(cve[CVE_ID_ATTRIBUTE], cve, "Invalid cpeMatch format: Expected a list inside nodes.")
                return False

            for cpe in node[CVE_CONFIGURATIONS_CPE_MATCH_ATTRIBUTE]:
                required_cpe_keys = {CONFIGURATION_VULNERABLE, CONFIGURATION_CRITERIA, CONFIGURATION_MATCH_CRITERIA_ID}
                missing_cpe_keys = required_cpe_keys - cpe.keys()

                if missing_cpe_keys:
                    log_error(cve[CVE_ID_ATTRIBUTE], cpe, f"Missing required cpeMatch fields: {', '.join(missing_cpe_keys)}")
                    return False

    return True


def process_cve_data(db):
    """Fetch, validate, and store CVE data in MongoDB."""
    setup_log()

    raw_data = fetch_cve_data()
    if not raw_data or RESPONSE_VULNERABILITIES_ATTRIBUTE not in raw_data:
        print("No CVE data received.")
        return

    initial_count = len(raw_data[RESPONSE_VULNERABILITIES_ATTRIBUTE])
    print(f"Total CVEs Fetched: {initial_count}")

    valid_cves = []
    seen_ids = set()
    loss_count = 0

    for item in raw_data[RESPONSE_VULNERABILITIES_ATTRIBUTE]:
        cve = item.get(RESPONSE_CVE_ATTRIBUTE, {})
        if validate_cve(cve) and cve[CVE_ID_ATTRIBUTE] not in seen_ids:
            seen_ids.add(cve[CVE_ID_ATTRIBUTE])
            valid_cves.append(cve)
        else:
            loss_count += 1

    print(f"Total CVEs Removed: {loss_count}")
    print(f"Total Valid CVEs Retained: {len(valid_cves)}")

    # Save to MongoDB
    if valid_cves:
        db.cves.insert_many(valid_cves)
        print(f"Inserted {len(valid_cves)} valid CVEs into the database.")
