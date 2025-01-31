from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # Import CORS middleware
from app.pipeline import process_cve_data
from app.database import connect_db, init_db
from app.routes import cve

# Initialize FastAPI app
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan function to initialize resources at startup
    and clean up if necessary on shutdown.
    """
    print("Starting up: Connecting to DB and processing data...")
    db = init_db()
    process_cve_data(db)
    yield  # Application runs after this
    print("Shutting down: Cleanup if necessary...")


# Initialize FastAPI app with lifespan
app = FastAPI(
    title="CVE FastAPI Backend",
    version="1.0",
    description="""
    This API provides access to Common Vulnerabilities and Exposures (CVE) data.
    It allows retrieving all stored CVEs or fetching specific CVEs by ID.

    **Features:**
    - ✅ Fetch all CVEs stored in MongoDB
    - ✅ Retrieve details of a CVE by ID
    - ✅ Data pipeline to validate and store CVE data
    - ✅ Automatic filtering of invalid CVEs
    - ✅ FastAPI documentation available at `/docs`
    """,
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:5500"],  # Allow your frontend origin
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Health Check Endpoint
@app.get("/health", tags=["Health"])
def health_check():
    """
    Perform a simple health check.

    **Returns:**
    - `200 OK`: If the API is running properly.
    """
    return {"status": "ok", "message": "CVE FastAPI Backend is running."}


# Include CVE Routes
app.include_router(cve.router)

# Run the API
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)