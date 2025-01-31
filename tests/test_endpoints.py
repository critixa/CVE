import pytest
from fastapi.testclient import TestClient
import mongomock
from app.main import app
from app.database import connect_db

client = TestClient(app)  # ✅ Create FastAPI test client

# ✅ Mock MongoDB using mongomock
@pytest.fixture
def mock_db(monkeypatch):
    mock_client = mongomock.MongoClient()
    mock_database = mock_client["test_db"]
    mock_collection = mock_database["cves"]

    # ✅ Insert mock data
    mock_collection.insert_many([
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
    ])

    # ✅ Patch `connect_db` to return the mock database
    monkeypatch.setattr("app.database.connect_db", lambda: mock_database)
    return mock_database

# ✅ Test fetching all CVEs
def test_get_all_cves(mock_db):
    response = client.get("/cve/?page=0&results_per_page=1")  
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "cves" in data
    assert len(data["cves"]) == 1  # Because we passed results_per_page=1

# ✅ Test fetching a CVE by ID
def test_get_cve_by_id(mock_db):
    response = client.get("/cve/CVE-2024-0001")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "CVE-2024-0001"
    assert data["sourceIdentifier"] == "nvd@nist.gov"

# ✅ Test fetching a non-existent CVE (should return 404)
def test_get_non_existent_cve(mock_db):
    response = client.get("/cve/CVE-9999-0001")
    assert response.status_code == 404
    assert response.json()["detail"] == "CVE not found"

# ✅ Test pagination (Ensuring different pages return different results)
def test_pagination(mock_db):
    response_page_1 = client.get("/cve/?page=0&results_per_page=1")
    response_page_2 = client.get("/cve/?page=1&results_per_page=1")

    assert response_page_1.status_code == 200
    assert response_page_2.status_code == 200

    data_page_1 = response_page_1.json()
    data_page_2 = response_page_2.json()

    assert data_page_1["cves"][0]["id"] != data_page_2["cves"][0]["id"]  # Different records on different pages

# ✅ Test FastAPI health check endpoint
def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "CVE FastAPI Backend is running."}
