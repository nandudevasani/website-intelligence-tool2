import express from 'express';
import axios from 'axios';
import cors from 'cors';
import https from 'https';
import dns from 'dns';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- Utilities ---
function normalizeDomain(input) {
  return input.trim().toLowerCase().replace(/^(https?:\/\/)/, '').replace(/^www\./, '').split('/')[0];
}

function buildUrl(domain, protocol = 'https') {
  return `${protocol}://${domain}`;
}

function extractRootDomain(url) {
  try {
    const hostname = url.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
    const parts = hostname.split('.');
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return hostname;
  } catch { return ''; }
}

// --- DNS Check ---
async function analyzeDNS(domain) {
  const result = { hasA: false };
  try {
    const a = await dns.promises.resolve4(domain);
    result.hasA = a.length > 0;
  } catch {}
  return result;
}

// --- SSL Check ---
function analyzeSSL(domain) {
  return new Promise(resolve => {
    const result = { valid: false };
    try {
      const req = https.request({ hostname: domain, port: 443, method: 'HEAD', timeout: 8000, rejectUnauthorized: false }, res => {
        const cert = res.socket.getPeerCertificate();
        if (cert && Object.keys(cert).length > 0) result.valid = res.socket.authorized;
        resolve(result);
      });
      req.on('error', () => resolve(result));
      req.on('timeout', () => { req.destroy(); resolve(result); });
      req.end();
    } catch { resolve(result); }
  });
}

// --- HTTP + Content Check ---
async function analyzeHTTP(domain) {
  const result = { isUp: false, statusCode: null, finalUrl: null };
  try {
    const res = await axios.get(buildUrl(domain), { timeout: 15000, maxRedirects: 10, validateStatus: () => true });
    result.isUp = true;
    result.statusCode = res.status;
    result.finalUrl = res.request?.res?.responseUrl || res.config?.url || null;
    return { result, html: typeof res.data === 'string' ? res.data : '' };
  } catch (err) {
    try {
      const res = await axios.get(buildUrl(domain, 'http'), { timeout: 15000, maxRedirects: 10, validateStatus: () => true });
      result.isUp = true;
      result.statusCode = res.status;
      result.finalUrl = res.request?.res?.responseUrl || res.config?.url || null;
      return { result, html: typeof res.data === 'string' ? res.data : '' };
    } catch {
      return { result, html: '' };
    }
  }
}

// --- Content Analysis ---
function analyzeContent(html, domain, finalUrl) {
  const analysis = { verdict: 'VALID', wordCount: 0 };
  if (!html || html.trim() === '') return { verdict: 'NO_CONTENT', wordCount: 0 };

  let body = html.replace(/<script[\s\S]*?<\/script>/gi, '')
                 .replace(/<style[\s\S]*?<\/style>/gi, '')
                 .replace(/<[^>]+>/g, ' ')
                 .replace(/\s+/g, ' ')
                 .trim();

  const words = body.split(' ').filter(w => w.length > 1);
  analysis.wordCount = words.length;

  // Minimal content
  if (words.length < 30) return { verdict: 'NO_CONTENT', wordCount: words.length };

  // Political campaign (simple check)
  const politicalDomain = /vote|elect|campaign|2\d{3}/i;
  const politicalContent = /vote|campaign|elect|election/i;
  if (politicalDomain.test(domain) || politicalContent.test(html)) return { verdict: 'POLITICAL_CAMPAIGN', wordCount: words.length };

  return analysis;
}

// --- Bulk Analysis Endpoint ---
app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) return res.status(400).json({ error: 'Provide domains' });
  if (domains.length > 200) return res.status(400).json({ error: 'Max 200 domains' });

  const results = [];
  for (const rawDomain of domains) {
    try {
      const domain = normalizeDomain(rawDomain);
      const [dnsRes, sslRes, httpRes] = await Promise.all([analyzeDNS(domain), analyzeSSL(domain), analyzeHTTP(domain)]);
      const { result: httpStatus, html } = httpRes;
      const content = analyzeContent(html, domain, httpStatus.finalUrl);

      let status = 'ACTIVE';
      let remark = content.verdict;
      let notes = 'valid';

      // DOWN / DEAD
      if (!dnsRes.hasA || !httpStatus.isUp) { status = 'DOWN'; remark = 'DOWN'; notes = 'not reachable'; }

      // Redirected
      const rootRequested = extractRootDomain(domain);
      const rootFinal = httpStatus.finalUrl ? extractRootDomain(httpStatus.finalUrl) : rootRequested;
      if (rootRequested !== rootFinal) { status = 'REDIRECTED'; remark = 'REDIRECTED'; notes = `redirected to ${rootFinal}`; }

      // NO_CONTENT
      if (content.verdict === 'NO_CONTENT' && status !== 'REDIRECTED') { status = 'NO_CONTENT'; notes = 'no content website'; }

      // Political campaign
      if (content.verdict === 'POLITICAL_CAMPAIGN' && status !== 'REDIRECTED') { status = 'POLITICAL_CAMPAIGN'; notes = 'political site'; }

      results.push({ domain, status, remark, notes });

    } catch (err) {
      results.push({ domain: normalizeDomain(rawDomain), status: 'ERROR', remark: 'ERROR', notes: err.message });
    }
  }

  res.json({ total: results.length, results });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
