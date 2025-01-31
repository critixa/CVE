
# CVE Management System

## Description
The CVE Management System is a web application that allows users to fetch, search, and view detailed CVE (Common Vulnerabilities and Exposures) data. The system fetches data from an external API, cleans and stores it in MongoDB, and exposes it through FastAPI endpoints. A simple frontend displays the data.

## Logical Approach to the Problem Statement
1. **Problem**: Needed to manage CVE data, allowing users to search and view detailed information.
2. **Approach**: 
   - Fetched CVE data from an external API.
   - Cleaned the data to remove duplicates, ensure proper date formatting, and verify the presence of important attributes.
   - Stored the cleaned data in MongoDB for easy retrieval.
   - Created two FastAPI endpoints: one for listing CVEs and another for fetching detailed information about each CVE.
   - Developed a basic frontend with HTML, CSS, and JavaScript for user interaction.
3. **Challenges**: Handling large amounts of data efficiently and managing errors during the data cleaning process.

## Quality of Code
- Adhered to consistent naming conventions and used comments for better readability.
- Ensured error handling by logging issues during data cleaning.
- Implemented pagination to avoid fetching large datasets all at once.

## Installation Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/cve-management.git
   cd cve-management
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   uvicorn app.main:app --reload
   ```

## Features
- Fetch CVEs with pagination.
- Search for CVEs by their ID.
- View detailed CVE information.
- Handle errors for non-existent CVEs.

## Code Structure
- **app/main.py**: Main FastAPI application.
- **app/models.py**: Data models for MongoDB.
- **frontend/**: Contains HTML, CSS, and JavaScript for the frontend.

## API Endpoints
- **GET /api/cves**: Retrieves a list of CVEs.
- **GET /api/cve/{id}**: Retrieves detailed information about a specific CVE.

## Future Improvements
- Implement log rotation for better error management.
- Add authentication to secure API access.
- Enhance the frontend with a more interactive design.

## Conclusion
This project demonstrates how to manage CVE data with FastAPI and MongoDB. It highlights the importance of data cleaning and validation, as well as efficient handling of large datasets.


