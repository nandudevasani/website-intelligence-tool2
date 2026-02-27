const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');

console.log("Starting server.js...");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Special cases
const POLITICAL_DOMAINS = ['vote4turner.com'];
const NO_CONTENT_THRESHOLD = 200; // mark pages with less than 200 words as "No Content"

async function analyzeDomain(domain) {
  let result = { domain, status: 'Valid', remark: '', notes: '' };

  try {
    const response = await axios.get('https://' + domain, { maxRedirects: 5, validateStatus: null });

    // Detect redirects
    if (response.request.res.responseUrl && !response.request.res.responseUrl.includes(domain)) {
      result.status = 'Invalid';
      result.remark = 'Redirected';
      result.notes = 'Redirect → ' + new URL(response.request.res.responseUrl).hostname;
      return result;
    }

    // Remove scripts/styles to count visible words
    const $ = cheerio.load(response.data);
    $('script, style, noscript').remove();
    const text = $('body').text().replace(/\s+/g, ' ').trim();
    const wordCount = text.split(' ').filter(w => w.length > 0).length;

    result.notes = `WC: ${wordCount}, SSL: ✅, HTTP: ${response.status}`;

    // No content check
    if (wordCount < NO_CONTENT_THRESHOLD) {
      result.status = 'Invalid';
      result.remark = 'No Content';
    }

    // Political sites
    if (POLITICAL_DOMAINS.includes(domain)) {
      result.remark = 'Political Campaign Site';
    }

  } catch (err) {
    result.status = 'Invalid';
    result.remark = 'Website not reachable';
  }

  return result;
}

// Bulk endpoint
app.post('/api/analyze-bulk', async (req, res) => {
  const domains = req.body.domains || [];
  const results = [];

  for (let domain of domains) {
    domain = domain.trim();
    if (!domain) continue;
    const analysis = await analyzeDomain(domain);
    results.push(analysis);
  }

  res.json(results);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
