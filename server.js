import express from 'express';
import axios from 'axios';
import cors from 'cors';
import dns from 'dns';
import https from 'https';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === UTILITY FUNCTIONS ===

function normalizeDomain(input) {
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^(https?:\/\/)/, '').replace(/\/.*$/, '').replace(/^www\./, '');
  return domain;
}

function buildUrl(domain, protocol = 'https') {
  return `${protocol}://${domain}`;
}

function extractRootDomain(url) {
  try {
    let hostname = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    const parts = hostname.split('.');
    if (parts.length >= 2) return parts.slice(-2).join('.');
    return hostname;
  } catch { return ''; }
}

// === DNS ANALYSIS ===

async function analyzeDNS(domain) {
  const results = { hasARecord: false, aRecords: [], error: null };
  try {
    const a = await dns.promises.resolve4(domain);
    results.aRecords = a;
    results.hasARecord = a.length > 0;
  } catch (err) { results.error = err.code || err.message; }
  return results;
}

// === SSL ANALYSIS ===

function analyzeSSL(domain) {
  return new Promise((resolve) => {
    const result = { valid: false, issuer: null, validFrom: null, validTo: null, daysRemaining: null, error: null };
    try {
      const req = https.request({ hostname: domain, port: 443, method: 'HEAD', timeout: 10000, rejectUnauthorized: false }, (res) => {
        const cert = res.socket.getPeerCertificate();
        if (cert && Object.keys(cert).length > 0) {
          result.valid = res.socket.authorized;
          result.issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
          result.validFrom = cert.valid_from || null;
          result.validTo = cert.valid_to || null;
          if (cert.valid_to) { result.daysRemaining = Math.floor((new Date(cert.valid_to) - new Date()) / 86400000); }
        }
        resolve(result);
      });
      req.on('error', e => { result.error = e.message; resolve(result); });
      req.on('timeout', () => { result.error = 'Timed out'; req.destroy(); resolve(result); });
      req.end();
    } catch (e) { result.error = e.message; resolve(result); }
  });
}

// === HTTP + REDIRECT ANALYSIS ===

async function fetchDomain(domain) {
  const result = { isUp: false, statusCode: null, finalUrl: null, html: '', error: null };
  const headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' };
  try {
    const res = await axios.get(buildUrl(domain), { timeout: 15000, maxRedirects: 10, validateStatus: () => true, headers });
    result.isUp = true;
    result.statusCode = res.status;
    result.finalUrl = res.request?.res?.responseUrl || res.config?.url || buildUrl(domain);
    result.html = typeof res.data === 'string' ? res.data : '';
  } catch (err) {
    result.error = err.code || err.message;
  }
  return result;
}

// === CONTENT ANALYSIS ===

function analyzeContent(html, domain, finalUrl) {
  const analysis = { verdict: 'VALID', confidence: 0, reasons: [], flags: [], notes: '' };

  // --- Redirect Check ---
  const rootInput = extractRootDomain(domain);
  const rootFinal = extractRootDomain(finalUrl);
  if (rootInput && rootFinal && rootInput !== rootFinal) {
    analysis.verdict = 'REDIRECTED';
    analysis.reasons.push(`Redirected to ${finalUrl}`);
    analysis.flags.push('REDIRECTED');
    analysis.notes = 'redirected';
    return analysis;
  }

  // --- Political Site Check ---
  const politicalKeywords = [/vote|elect|campaign|mayor|senate|commissioner/i];
  if (politicalKeywords.some(p => p.test(domain)) || politicalKeywords.some(p => p.test(html))) {
    analysis.verdict = 'POLITICAL_CAMPAIGN';
    analysis.reasons.push('Political site detected');
    analysis.flags.push('POLITICAL_CAMPAIGN');
    analysis.notes = 'political site';
    return analysis;
  }

  // --- Minimal Content Check ---
  let bodyText = html.replace(/<script[\s\S]*?<\/script>/gi, '')
                     .replace(/<style[\s\S]*?<\/style>/gi, '')
                     .replace(/<[^>]+>/g, ' ')
                     .replace(/\s+/g, ' ').trim();
  const words = bodyText.split(/\s+/).filter(w => w.length > 1);
  const wordCount = words.length;

  if (wordCount < 30) {
    analysis.verdict = 'NO_CONTENT';
    analysis.reasons.push('Page has very little content');
    analysis.notes = 'no content website';
    return analysis;
  }

  analysis.verdict = 'ACTIVE';
  analysis.reasons.push('Valid content');
  analysis.notes = 'valid content';
  return analysis;
}

// === SINGLE DOMAIN ANALYSIS ===

async function analyzeDomain(domain) {
  const dnsResults = await analyzeDNS(domain);
  const sslResults = await analyzeSSL(domain);
  const httpResults = await fetchDomain(domain);
  const contentAnalysis = analyzeContent(httpResults.html, domain, httpResults.finalUrl || buildUrl(domain));

  return {
    domain,
    status: contentAnalysis.verdict,
    remark: contentAnalysis.verdict,
    notes: contentAnalysis.notes,
    dns: dnsResults,
    ssl: sslResults,
    http: httpResults,
    wordCount: httpResults.html ? httpResults.html.split(/\s+/).length : 0,
    finalUrl: httpResults.finalUrl
  };
}

// === BULK ANALYSIS ===

app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: 'Provide an array of domains, one per line' });
  }

  const results = [];
  for (const rawDomain of domains) {
    const domain = normalizeDomain(rawDomain);
    try {
      const analysis = await analyzeDomain(domain);
      results.push(analysis);
      console.log(`[OK] ${domain} -> ${analysis.status}`);
    } catch (err) {
      results.push({ domain, status: 'ERROR', remark: 'ERROR', notes: err.message });
      console.error(`[ERR] ${domain} -> ${err.message}`);
    }
  }
  res.json({ total: results.length, results });
});

// === HEALTH CHECK ===

app.get('/api/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// === START SERVER ===

app.listen(PORT, () => {
  console.log(`Website Intelligence Tool running at http://localhost:${PORT}`);
});
