document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const domains = document.getElementById('domainInput').value
        .split('\n').map(d => d.trim()).filter(d => d);

    if (!domains.length) return alert('Please enter domains');

    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = '<tr><td colspan="5">Processing domains...</td></tr>';

    try {
        const res = await fetch('/api/analyze/bulk', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domains })
        });
        const results = await res.json();
        renderTable(results);
        renderChart(results);
    } catch (err) {
        alert('Server error. Make sure npm start is running.');
    }
});

function renderTable(results) {
    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = results.map(r => {
        const statusClass = `status-${r.status.toLowerCase()}`;
        return `
            <tr>
                <td>${r.domain}</td>
                <td class="${statusClass}">${r.status}</td>
                <td>${r.remark}</td>
                <td>${r.notes}</td>
                <td><input type="text" class="insight-input" placeholder="Add note..."></td>
            </tr>
        `;
    }).join('');
}

function renderChart(results) {
    const ctx = document.getElementById('statusChart').getContext('2d');
    const stats = results.reduce((acc, r) => {
        acc[r.status] = (acc[r.status] || 0) + 1;
        return acc;
    }, {});

    if (window.myChart) window.myChart.destroy();
    window.myChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(stats),
            datasets: [{ 
                data: Object.values(stats), 
                backgroundColor: ['#2e7d32', '#c62828', '#f9a825', '#ef6c00'] 
            }]
        }
    });
}

document.getElementById('exportBtn').addEventListener('click', () => {
    const wb = XLSX.utils.table_to_book(document.getElementById('resultsTable'));
    XLSX.writeFile(wb, 'domain-analysis.xlsx');
});
