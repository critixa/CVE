const resultsPerPageSelect = document.getElementById('results-per-page');
const cveTableBody = document.getElementById('cve-table-body');
const totalRecordsElement = document.getElementById('total-records');
let currentPage = 0; // Current page starts from 0

// Function to fetch CVE data with pagination
async function fetchCveData(resultsPerPage, page) {
  try {
    const skip = page * resultsPerPage; // Calculate the number of records to skip
    const response = await fetch(`http://localhost:8000/cve/?limit=${resultsPerPage}&skip=${skip}`);
    const data = await response.json();

    // Update the total records count
    totalRecordsElement.innerHTML = `Total Records: ${data.total}`;

    // Clear the existing rows in the table
    cveTableBody.innerHTML = '';

    // Add new rows to the table
    data.cves.forEach(cve => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td><a href="detail.html?cve_id=${cve.id}">${cve.id}</a></td>
        <td>${cve.sourceIdentifier}</td>
        <td>${new Date(cve.published).toLocaleDateString()}</td>
        <td>${new Date(cve.lastModified).toLocaleDateString()}</td>
        <td>${cve.vulnStatus}</td>
      `;
      cveTableBody.appendChild(row);
    });
  } catch (error) {
    console.error('Error fetching CVE data:', error);
  }
}

// Initial fetch with default results per page (10)
fetchCveData(10, currentPage);

// Event listener for results per page dropdown change
resultsPerPageSelect.addEventListener('change', (event) => {
  const resultsPerPage = event.target.value;
  fetchCveData(resultsPerPage, currentPage);
});

// Event listeners for pagination (Next/Previous buttons)
document.getElementById('next-page').addEventListener('click', () => {
  currentPage++;
  const resultsPerPage = resultsPerPageSelect.value;
  fetchCveData(resultsPerPage, currentPage);
});

document.getElementById('prev-page').addEventListener('click', () => {
  if (currentPage > 0) {
    currentPage--;
    const resultsPerPage = resultsPerPageSelect.value;
    fetchCveData(resultsPerPage, currentPage);
  }
});