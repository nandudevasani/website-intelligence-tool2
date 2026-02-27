document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const domains = document.getElementById('domainInput').value
        .split('\n').map(d => d.trim()).filter(d => d);

    if (!domains.length) return alert('Enter domains first');

    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = '<tr><td colspan="4">Processing...</td></tr>';

    const res = await fetch('/api/analyze/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains })
    });

    const results = await res.json();
    renderTable(results);
    renderChart(results);
});

function renderTable(results) {
    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = results.map(r => `
        <tr><td>${r.domain}</td><td>${r.status}</td><td>${r.remark}</td><td>${r.notes}</td></tr>
    `).join('');
}

function renderChart(results) {
    const ctx = document.getElementById('statusChart').getContext('2d');
    const stats = results.reduce((acc, r) => {
        acc[r.status] = (acc[r.status] || 0) + 1;
        return acc;
    }, {});

    if (window.myChart) window.myChart.destroy();
    window.myChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(stats),
            datasets: [{ data: Object.values(stats), backgroundColor: ['#4CAF50', '#F44336', '#FFC107'] }]
        }
    });
}

document.getElementById('exportBtn').addEventListener('click', () => {
    const wb = XLSX.utils.table_to_book(document.getElementById('resultsTable'));
    XLSX.writeFile(wb, 'analysis.xlsx');
});
