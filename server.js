import express from 'express';
import axios from 'axios';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Utility Functions ---
function normalizeDomain(domain) {
  let d = domain.trim().toLowerCase();
  d = d.replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '').replace(/^www\./, '');
  return d;
}

function extractRootDomain(url) {
  try {
    const hostname = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    const parts = hostname.split('.');
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return hostname;
  } catch {
    return url;
  }
}

// --- Core Content Analysis ---
function analyzeHtmlContent(html, domain, finalUrl) {
  const analysis = { status: 'ACTIVE', remark: '', notes: '' };

  // 1️⃣ Redirect check first
  if (finalUrl) {
    const rootInput = extractRootDomain(domain);
    const rootFinal = extractRootDomain(finalUrl);
    if (rootInput !== rootFinal) {
      analysis.status = 'REDIRECTED';
      analysis.remark = 'REDIRECTED';
      analysis.notes = 'redirected';
      return analysis;
    }
  }

  // 2️⃣ Political site detection
  const politicalPatterns = [/vote/i, /elect/i, /campaign/i, /mayor/i, /senate/i, /commissioner/i];
  if (politicalPatterns.some(p => p.test(domain)) || politicalPatterns.some(p => p.test(html))) {
    analysis.status = 'POLITICAL_CAMPAIGN';
    analysis.remark = 'POLITICAL_CAMPAIGN';
    analysis.notes = 'political site';
    return analysis;
  }

  // 3️⃣ Content check
  let bodyText = html.replace(/<script[\s\S]*?<\/script>/gi, '')
                     .replace(/<style[\s\S]*?<\/style>/gi, '')
                     .replace(/<[^>]+>/g, ' ')
                     .replace(/\s+/g, ' ').trim();

  const words = bodyText.split(/\s+/).filter(w => w.length > 1);

  if (words.length < 30) {
    analysis.status = 'NO_CONTENT';
    analysis.remark = 'NO_CONTENT';
    analysis.notes = 'no content website';
    return analysis;
  }

  // Default active/valid
  analysis.status = 'ACTIVE';
  analysis.remark = 'ACTIVE';
  analysis.notes = 'valid content';
  return analysis;
}

// --- Single Domain Analysis ---
async function analyzeDomain(domain) {
  const normalized = normalizeDomain(domain);
  let finalUrl = null;
  let html = '';

  try {
    const res = await axios.get(`https://${normalized}`, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });
    finalUrl = res.request?.res?.responseUrl || res.config?.url;
    html = typeof res.data === 'string' ? res.data : '';
  } catch (err) {
    return { domain: normalized, status: 'DOWN', remark: 'DOWN', notes: 'site not reachable' };
  }

  const analysis = analyzeHtmlContent(html, normalized, finalUrl);
  return { domain: normalized, ...analysis };
}

// --- API Endpoints ---
// Single domain
app.post('/api/analyze', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain is required' });
  const result = await analyzeDomain(domain);
  res.json(result);
});

// Bulk domains (one per line)
app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body; // string with one domain per line
  if (!domains) return res.status(400).json({ error: 'Provide domains as string, one per line' });

  const domainList = domains.split('\n').map(d => d.trim()).filter(d => d.length > 0);
  if (domainList.length === 0) return res.status(400).json({ error: 'No valid domains found' });

  const results = [];
  for (const d of domainList) {
    const r = await analyzeDomain(d);
    results.push(r);
  }

  res.json({ total: results.length, results });
});

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// Start server
app.listen(PORT, () => {
  console.log(`\n=== Website Intelligence Basic ===`);
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`POST /api/analyze  -> single domain`);
  console.log(`POST /api/analyze/bulk -> bulk domains (one per line)\n`);
});
