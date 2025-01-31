import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "cve_db")
CVE_API_URL = os.getenv("CVE_API_URL", "https://example.com/api/cves")
LOG_FILE = os.getenv("LOG_FILE", "data_pipeline_errors.log")


RESPONSE_VULNERABILITIES_ATTRIBUTE = "vulnerabilities"
RESPONSE_CVE_ATTRIBUTE = "cve"

CVE_ID_ATTRIBUTE = "id"
CVE_SOURCE_ATTRIBUTE = "sourceIdentifier"
CVE_PUBLISHED_ATTRIBUTE = "published"
CVE_LAST_MODIFIED_ATTRIBUTE = "lastModified"
CVE_VUL_STATUS_ATTRIBUTE = "vulnStatus"
CVE_METRICS_ATTRIBUTE = "metrics"
CVE_CONFIGURATIONS_ATTRIBUTE = "configurations"

METRICS_CVSS_V2 = "cvssMetricV2"
METRICS_CVSS_V3 = "cvssMetricV3"

METRIC_DATA_SOURCE = "source"
METRIC_DATA_TYPE = "type"
METRIC_DATA_CVSS_DATA = "cvssData"
METRIC_DATA_BASE_SEVERITY = "baseSeverity"
METRIC_DATA_EXPLOITABILITY_SCORE = "exploitabilityScore"
METRIC_IMPACT_SCORE = "impactScore"
METRIC_DATA_AC_INSUF_INFO = "acInsufInfo"
METRIC_DATA_OBTAIN_ALL_PRIVILEGE = "obtainAllPrivilege"
METRIC_DATA_USER_PRIVILEGE = "obtainUserPrivilege"
METRIC_DATA_OBTAIN_OTHER_PRIVILEGE = "obtainOtherPrivilege"
METRIC_DATA_USER_INTERACTION_REQUIRED = "userInteractionRequired"


CVSS_DATA_VERSION = "version"
CVSS_DATA_VECTOR_STRING = "vectorString"
CVSS_DATA_BASE_SCORE = "baseScore"
CVSS_DATA_ACCESS_VECTOR = "accessVector"
CVSS_DATA_ACCESS_COMPLEXITY = "accessComplexity"
CVSS_DATA_AUTHENTICATION = "authentication"
CVSS_DATA_CONFIDENTIALITY_IMPACT = "confidentialityImpact"
CVSS_DATA_INTEGRITY_IMPACT = "integrityImpact"
CVSS_DATA_AVAILABILITY_IMPACT = "availabilityImpact"

CVE_CONFIGURATIONS_NODES_ATTRIBUTE = "nodes"
CVE_CONFIGURATIONS_CPE_MATCH_ATTRIBUTE = "cpeMatch"

CONFIGURATION_VULNERABLE = "vulnerable"
CONFIGURATION_CRITERIA = "criteria"
CONFIGURATION_MATCH_CRITERIA_ID = "matchCriteriaId"