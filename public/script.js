document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const domains = document.getElementById('domainInput').value.split('\n').filter(d => d.trim());
    if (!domains.length) return alert('Enter domains');

    const tbody = document.querySelector('#resultsTable tbody');
    tbody.innerHTML = '<tr><td colspan="5">Scanning...</td></tr>';

    const res = await fetch('/api/analyze/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains })
    });

    const data = await res.json();
    tbody.innerHTML = data.map(r => `
        <tr class="row-${r.status.toLowerCase()}">
            <td>${r.domain}</td>
            <td class="status-cell">${r.status}</td>
            <td>${r.remark}</td>
            <td>${r.notes}</td>
            <td><input type="text" placeholder="Add custom insight..."></td>
        </tr>
    `).join('');
});

document.getElementById('exportBtn').addEventListener('click', () => {
    const wb = XLSX.utils.table_to_book(document.getElementById('resultsTable'));
    XLSX.writeFile(wb, 'domain_intelligence.xlsx');
});
