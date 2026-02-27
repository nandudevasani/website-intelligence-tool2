import express from 'express';
import axios from 'axios';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === UTILITIES ===
function normalizeDomain(input) {
  return input.trim().toLowerCase().replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '').replace(/^www\./, '');
}

function extractRootDomain(url) {
  try {
    let host = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    const parts = host.split('.');
    return parts.length >= 2 ? parts.slice(-2).join('.') : host;
  } catch { return ''; }
}

async function checkDNS(domain) {
  try {
    const a = await dns.promises.resolve4(domain);
    return a.length > 0;
  } catch { return false; }
}

async function fetchHTML(domain) {
  const urls = [`https://${domain}`, `http://${domain}`];
  for (const url of urls) {
    try {
      const res = await axios.get(url, { timeout: 15000, maxRedirects: 10, validateStatus: () => true });
      return { html: typeof res.data === 'string' ? res.data : '', finalUrl: res.request?.res?.responseUrl || res.config?.url || url, statusCode: res.status };
    } catch {}
  }
  return { html: '', finalUrl: null, statusCode: null };
}

function analyzeContent(html) {
  const text = html.replace(/<script[\s\S]*?<\/script>/gi, '')
                   .replace(/<style[\s\S]*?<\/style>/gi, '')
                   .replace(/<[^>]+>/g, ' ')
                   .replace(/\s+/g, ' ').trim();
  const words = text.split(/\s+/).filter(w => w.length > 1);
  return { wordCount: words.length };
}

// === MAIN ANALYSIS LOGIC ===
function determineStatus(domain, finalUrl, wordCount, html) {
  const rootDomain = extractRootDomain(domain);
  let status = 'ACTIVE', remark = 'ACTIVE', notes = 'valid content';

  // 1️⃣ DOWN / unreachable
  if (!finalUrl) {
    status = remark = 'DOWN';
    notes = 'site not reachable';
    return { status, remark, notes };
  }

  // 2️⃣ REDIRECTED
  const finalRoot = extractRootDomain(finalUrl);
  if (rootDomain !== finalRoot) {
    status = remark = 'REDIRECTED';
    notes = 'redirected';
    return { status, remark, notes };
  }

  // 3️⃣ POLITICAL CAMPAIGN
  const politicalPatterns = [/vote/i, /campaign/i, /elect/i, /ballot/i];
  if (politicalPatterns.some(p => p.test(html)) || /vote|elect/.test(domain)) {
    status = remark = 'POLITICAL_CAMPAIGN';
    notes = 'political site';
    return { status, remark, notes };
  }

  // 4️⃣ NO CONTENT
  if (wordCount < 50) {
    status = remark = 'NO_CONTENT';
    notes = 'no content website';
    return { status, remark, notes };
  }

  // 5️⃣ Otherwise ACTIVE
  return { status, remark, notes };
}

// === SINGLE DOMAIN ANALYSIS ===
app.post('/api/analyze', async (req, res) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain) return res.status(400).json({ error: 'Domain is required' });

  const domain = normalizeDomain(rawDomain);
  const dnsValid = await checkDNS(domain);
  const { html, finalUrl } = await fetchHTML(domain);

  const wordCount = analyzeContent(html).wordCount;
  const result = determineStatus(domain, finalUrl && dnsValid ? finalUrl : null, wordCount, html);

  res.json({ domain, ...result });
});

// === BULK ANALYSIS ===
app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains)) return res.status(400).json({ error: 'Provide domains array' });

  const results = [];
  for (const raw of domains) {
    const domain = normalizeDomain(raw);
    const dnsValid = await checkDNS(domain);
    const { html, finalUrl } = await fetchHTML(domain);
    const wordCount = analyzeContent(html).wordCount;
    results.push({ domain, ...determineStatus(domain, finalUrl && dnsValid ? finalUrl : null, wordCount, html) });
  }
  res.json({ total: results.length, results });
});

// === HEALTH CHECK ===
app.get('/api/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
