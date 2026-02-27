document.getElementById('analyzeBtn').addEventListener('click', async () => {
  const domains = document.getElementById('domainInput').value
    .split('\n')
    .map(d => d.trim())
    .filter(d => d);

  if (!domains.length) return alert('Enter at least one domain');

  const res = await fetch('/api/analyze-bulk', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domains })
  });

  const results = await res.json();
  renderTable(results);
  renderChart(results);
});

document.getElementById('exportBtn').addEventListener('click', () => {
  const table = document.getElementById('resultsTable');
  const wb = XLSX.utils.table_to_book(table);
  XLSX.writeFile(wb, 'domain-analysis.xlsx');
});

function renderTable(results) {
  const tbody = document.querySelector('#resultsTable tbody');
  tbody.innerHTML = '';
  results.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${r.domain}</td><td>${r.status}</td><td>${r.remark}</td><td>${r.notes}</td>`;
    tbody.appendChild(tr);
  });
}

function renderChart(results) {
  const ctx = document.getElementById('statusChart').getContext('2d');
  const counts = { Valid: 0, Invalid: 0 };
  results.forEach(r => counts[r.status] ? counts[r.status]++ : 0);

  if (window.statusChartInstance) window.statusChartInstance.destroy();

  window.statusChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Valid', 'Invalid'],
      datasets: [{
        label: '# of Domains',
        data: [counts.Valid, counts.Invalid],
        backgroundColor: ['#4CAF50', '#F44336']
      }]
    },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}
