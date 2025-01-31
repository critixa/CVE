document.addEventListener('DOMContentLoaded', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const cveId = urlParams.get('cve_id');

    if (cveId) {
        fetchCVE(cveId);
    }
});

async function fetchCVE(cveId) {
    try {
        const response = await fetch(`http://localhost:8000/cve/${cveId}`);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();

        // Fill CVE Basic Details
        document.getElementById('cve-id').textContent = data.id;
        document.getElementById('description').textContent = data.description || "No description available";

        // Extract Metrics
        const metrics = data.metrics || {};
        const cvssData = metrics.cvssData || {};

        document.getElementById('severity').textContent = metrics.baseSeverity || "N/A";
        document.getElementById('score').textContent = cvssData.baseScore || "N/A";
        document.getElementById('vectorString').textContent = cvssData.vectorString || "N/A";

        // Access Information Table
        document.getElementById('accessVector').textContent = cvssData.accessVector || "N/A";
        document.getElementById('accessComplexity').textContent = cvssData.accessComplexity || "N/A";
        document.getElementById('authentication').textContent = cvssData.authentication || "N/A";
        document.getElementById('confidentialityImpact').textContent = cvssData.confidentialityImpact || "N/A";
        document.getElementById('integrityImpact').textContent = cvssData.integrityImpact || "N/A";
        document.getElementById('availabilityImpact').textContent = cvssData.availabilityImpact || "N/A";

        // Scores Section
        document.getElementById('exploitabilityScore').textContent = metrics.exploitabilityScore || "N/A";
        document.getElementById('impactScore').textContent = metrics.impactScore || "N/A";

        // Populate CPE Table
        const cpeTableBody = document.getElementById('cpe-table-body');
        cpeTableBody.innerHTML = ""; // Clear old data

        if (data.configurations && data.configurations.length > 0) {
            data.configurations.forEach(config => {
                config.nodes.forEach(node => {
                    node.cpeMatch.forEach(cpe => {
                        const row = document.createElement('tr');

                        row.innerHTML = `
                            <td>${cpe.criteria || "N/A"}</td>
                            <td>${cpe.matchCriteriaId || "N/A"}</td>
                            <td>${cpe.vulnerable ? "Yes" : "No"}</td>
                        `;

                        cpeTableBody.appendChild(row);
                    });
                });
            });
        } else {
            cpeTableBody.innerHTML = "<tr><td colspan='3'>No CPE data available</td></tr>";
        }

    } catch (error) {
        console.error("Error fetching CVE details:", error);
        document.getElementById('cve-id').textContent = "Error loading CVE details";
    }
}
