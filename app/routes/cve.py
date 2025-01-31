from typing import List

from fastapi import APIRouter, HTTPException, Depends
from pymongo.collection import Collection
from app.config import CVE_ID_ATTRIBUTE, CVE_SOURCE_ATTRIBUTE, CVE_PUBLISHED_ATTRIBUTE, CVE_LAST_MODIFIED_ATTRIBUTE, \
    CVE_VUL_STATUS_ATTRIBUTE
from app.database import connect_db
from app.models import CVEModel
import traceback

router = APIRouter(prefix="/cve", tags=["CVE Data"])

def get_cve_collection():
    """Dependency function to get MongoDB collection."""
    db = connect_db()
    return db.cves


@router.get(
    "/",
    summary="Fetch All CVEs with Selected Fields and Pagination",
    description="""Retrieve a list of all stored CVEs with selected fields and pagination support.
    You can specify the page and number of results per page.""",
    responses={
        200: {
            "description": "List of CVEs with selected fields and total count.",
            "content": {
                "application/json": {
                    "example": {
                        "total": 2,
                        "cves": [
                            {
                                "id": "CVE-2024-0001",
                                "sourceIdentifier": "nvd@nist.gov",
                                "published": "2024-01-01T10:00:00Z",
                                "lastModified": "2024-01-15T12:00:00Z",
                                "vulnStatus": "Analyzed"
                            },
                            {
                                "id": "CVE-2024-0002",
                                "sourceIdentifier": "cve@mitre.org",
                                "published": "2024-01-05T08:00:00Z",
                                "lastModified": "2024-01-20T15:30:00Z",
                                "vulnStatus": "Under Investigation"
                            }
                        ]
                    }
                }
            }
        },
        500: {
            "description": "Internal Server Error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Internal Server Error while fetching CVEs"
                    }
                }
            }
        }
    }
)
async def get_cves(page: int = 1, results_per_page: int = 10, collection: Collection = Depends(get_cve_collection)):
    """
    Fetch all stored CVEs and return only selected fields with pagination.

    Args:
        page (int): The page number (default is 1).
        results_per_page (int): The number of records per page (default is 10).
        collection (Collection, optional): MongoDB collection dependency. Defaults to `get_cve_collection()`.

    Returns:
        dict: A dictionary containing the total number of CVEs and the list of CVEs for the current page.
    """
    skip = (page - 1) * results_per_page
    try:
        # Fetch data with pagination, selecting only the required fields
        cves_cursor = collection.find({}, {
            "_id": 0, 
            CVE_ID_ATTRIBUTE: 1, 
            CVE_SOURCE_ATTRIBUTE: 1, 
            CVE_PUBLISHED_ATTRIBUTE: 1, 
            CVE_LAST_MODIFIED_ATTRIBUTE: 1, 
            CVE_VUL_STATUS_ATTRIBUTE: 1
        }).skip(skip).limit(results_per_page)
        
        cves_list = list(cves_cursor)  # Convert cursor to list

        # Get the total count of CVEs for pagination info
        total_count = collection.count_documents({})

        return {
            "total": total_count,
            "cves": cves_list
        }

    except Exception as e:
        error_message = str(e)
        traceback_info = traceback.format_exc()
        print(f"Error fetching CVEs: {error_message}\n{traceback_info}")

        raise HTTPException(status_code=500, detail="Internal Server Error while fetching CVEs")


@router.get(
    "/{cve_id}",
    response_model=CVEModel,
    summary="Fetch a CVE by ID",
    description="""Retrieve details of a specific CVE record by providing its unique CVE ID.""",
    responses={
        200: {
            "description": "Details of a specific CVE.",
            "content": {
                "application/json": {
                    "example": {
                        "id": "CVE-2024-0001",
                        "sourceIdentifier": "nvd@nist.gov",
                        "published": "2024-01-01T10:00:00Z",
                        "lastModified": "2024-01-15T12:00:00Z",
                        "vulnStatus": "Analyzed",
                        "metrics": {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "accessVector": "NETWORK",
                                "accessComplexity": "LOW",
                                "authentication": "NONE",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            },
                            "baseSeverity": "CRITICAL",
                            "exploitabilityScore": 3.9,
                            "impactScore": 2.9,
                            "acInsufInfo": False,
                            "obtainAllPrivilege": False,
                            "obtainUserPrivilege": False,
                            "obtainOtherPrivilege": False,
                            "userInteractionRequired": False
                        }
                    }
                }
            }
        },
        404: {
            "description": "CVE ID not found.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "CVE not found"
                    }
                }
            }
        }
    }
)
async def get_cve_by_id(cve_id: str, collection: Collection = Depends(get_cve_collection)):
    """
    Retrieve a specific CVE by ID.

    Args:
        cve_id (str): Unique CVE identifier.
        collection (Collection, optional): MongoDB collection dependency. Defaults to `get_cve_collection()`.

    Returns:
        CVEModel: Details of the requested CVE.
    """
    try:
        cve = collection.find_one({"id": cve_id}, {"_id": 0})

        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")

        # Preprocess the 'metrics' field to match the expected schema
        metrics = cve.get("metrics", {})
        cvss_metric = None

        if "cvssMetricV2" in metrics:
            cvss_metric = metrics["cvssMetricV2"]
        elif "cvssMetricV3" in metrics:
            cvss_metric = metrics["cvssMetricV3"]

        # Flatten list if necessary
        if isinstance(cvss_metric, list) and len(cvss_metric) > 0:
            cvss_metric = cvss_metric[0]  # Take the first metric object

        # Ensure only the required fields exist
        if cvss_metric and isinstance(cvss_metric, dict):
            cve["metrics"] = {
                "source": cvss_metric.get("source"),
                "type": cvss_metric.get("type"),
                "cvssData": cvss_metric.get("cvssData"),
                "baseSeverity": cvss_metric.get("baseSeverity"),
                "exploitabilityScore": cvss_metric.get("exploitabilityScore"),
                "impactScore": cvss_metric.get("impactScore"),
                "acInsufInfo": cvss_metric.get("acInsufInfo"),
                "obtainAllPrivilege": cvss_metric.get("obtainAllPrivilege"),
                "obtainUserPrivilege": cvss_metric.get("obtainUserPrivilege"),
                "obtainOtherPrivilege": cvss_metric.get("obtainOtherPrivilege"),
                "userInteractionRequired": cvss_metric.get("userInteractionRequired"),
            }
        else:
            cve["metrics"] = None  # Remove metrics if invalid

        return cve

    except Exception as e:
        error_message = str(e)
        traceback_info = traceback.format_exc()
        print(f"Error fetching CVE {cve_id}: {error_message}\n{traceback_info}")

        raise HTTPException(status_code=500, detail="Internal Server Error while fetching CVE")
