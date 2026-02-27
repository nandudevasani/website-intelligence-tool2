import express from 'express';
import axios from 'axios';
import cors from 'cors';
import https from 'https';
import dns from 'dns';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === Utility Functions ===
function normalizeDomain(input) {
  let domain = input.trim().toLowerCase();
  domain = domain.replace(/^(https?:\/\/)/, '');
  domain = domain.replace(/\/.*$/, '');
  domain = domain.replace(/^www\./, '');
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

// === DNS Analysis ===
async function analyzeDNS(domain) {
  const results = { hasARecord: false, hasMXRecord: false, hasNSRecord: false, aRecords: [], mxRecords: [], nsRecords: [], cnameRecords: [], txtRecords: [], error: null };
  try {
    try { const a = await dns.promises.resolve4(domain); results.aRecords = a; results.hasARecord = a.length > 0; } catch {}
    try { const mx = await dns.promises.resolveMx(domain); results.mxRecords = mx.map(r => ({ priority: r.priority, exchange: r.exchange })); results.hasMXRecord = mx.length > 0; } catch {}
    try { const ns = await dns.promises.resolveNs(domain); results.nsRecords = ns; results.hasNSRecord = ns.length > 0; } catch {}
    try { const cn = await dns.promises.resolveCname(domain); results.cnameRecords = cn; } catch {}
    try { const tx = await dns.promises.resolveTxt(domain); results.txtRecords = tx.map(r => r.join('')); } catch {}
  } catch (err) { results.error = err.message; }
  return results;
}

// === SSL Analysis ===
function analyzeSSL(domain) {
  return new Promise((resolve) => {
    const result = { valid: false, issuer: null, subject: null, validFrom: null, validTo: null, daysRemaining: null, protocol: null, error: null };
    try {
      const req = https.request({ hostname: domain, port: 443, method: 'HEAD', timeout: 10000, rejectUnauthorized: false }, (res) => {
        const cert = res.socket.getPeerCertificate();
        if (cert && Object.keys(cert).length > 0) {
          result.valid = res.socket.authorized;
          result.issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Unknown') : 'Unknown';
          result.subject = cert.subject ? (cert.subject.CN || 'Unknown') : 'Unknown';
          result.validFrom = cert.valid_from || null;
          result.validTo = cert.valid_to || null;
          if (cert.valid_to) { const exp = new Date(cert.valid_to); result.daysRemaining = Math.floor((exp - new Date()) / 86400000); }
          result.protocol = res.socket.getProtocol ? res.socket.getProtocol() : null;
        }
        resolve(result);
      });
      req.on('error', (e) => { result.error = e.message; resolve(result); });
      req.on('timeout', () => { result.error = 'Timed out'; req.destroy(); resolve(result); });
      req.end();
    } catch (e) { result.error = e.message; resolve(result); }
  });
}

// === HTTP Status Analysis ===
async function analyzeHTTPStatus(domain) {
  const result = { isUp: false, statusCode: null, statusText: null, responseTime: null, finalUrl: null, redirectChain: [], headers: {}, error: null };
  const start = Date.now();
  const hdrs = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5' };

  try {
    const res = await axios.get(buildUrl(domain), { timeout: 15000, maxRedirects: 10, validateStatus: () => true, headers: hdrs });
    result.isUp = true; result.statusCode = res.status; result.statusText = res.statusText;
    result.responseTime = Date.now() - start;
    result.finalUrl = res.request?.res?.responseUrl || res.config?.url || null;
    result.headers = { server: res.headers['server'] || null, poweredBy: res.headers['x-powered-by'] || null, contentType: res.headers['content-type'] || null };
    return { result, html: typeof res.data === 'string' ? res.data : '' };
  } catch (err) {
    result.responseTime = Date.now() - start;
    try {
      const fb = await axios.get(buildUrl(domain, 'http'), { timeout: 15000, maxRedirects: 10, validateStatus: () => true, headers: { 'User-Agent': 'Mozilla/5.0' } });
      result.isUp = true; result.statusCode = fb.status; result.statusText = fb.statusText;
      result.finalUrl = fb.request?.res?.responseUrl || fb.config?.url || null;
      return { result, html: typeof fb.data === 'string' ? fb.data : '' };
    } catch (e2) { result.error = err.code || err.message; return { result, html: '' }; }
  }
}

// === Content Analysis ===
function analyzeContent(html, domain, finalUrl) {
  const analysis = { verdict: 'VALID', confidence: 0, reasons: [], flags: [], redirectInfo: null, details: { title: null, metaDescription: null, hasBody: false, bodyTextLength: 0, wordCount: 0, uniqueWordCount: 0, headings: [], links: { internal: 0, external: 0 }, images: 0, forms: 0, scripts: 0, iframes: 0 } };

  if (!html || html.trim().length === 0) {
    analysis.verdict = 'NO_CONTENT'; analysis.confidence = 95; analysis.reasons.push('Empty HTML'); return analysis;
  }

  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  analysis.details.title = titleMatch ? titleMatch[1].trim().replace(/\s+/g, ' ') : null;

  const metaDescMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([\s\S]*?)["']/i);
  analysis.details.metaDescription = metaDescMatch ? metaDescMatch[1].trim() : null;

  let bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  let bodyText = bodyMatch ? bodyMatch[1] : html;
  bodyText = bodyText.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<noscript[\s\S]*?<\/noscript>/gi, '').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ').replace(/&#\d+;/gi, ' ').replace(/\s+/g, ' ').trim();

  analysis.details.hasBody = bodyText.length > 0;
  analysis.details.bodyTextLength = bodyText.length;
  const words = bodyText.split(/\s+/).filter(w => w.length > 1);
  analysis.details.wordCount = words.length;
  const uniqueWords = new Set(words.map(w => w.toLowerCase()));
  analysis.details.uniqueWordCount = uniqueWords.size;

  const headingMatches = html.match(/<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/gi) || [];
  analysis.details.headings = headingMatches.map(h => h.replace(/<[^>]+>/g, '').trim()).filter(h => h.length > 0);
  analysis.details.images = (html.match(/<img[\s ]/gi) || []).length;
  analysis.details.forms = (html.match(/<form[\s ]/gi) || []).length;
  analysis.details.scripts = (html.match(/<script[\s>]/gi) || []).length;
  analysis.details.iframes = (html.match(/<iframe[\s ]/gi) || []).length;

  const linkMatches = html.match(/<a[^>]+href=["']([^"']+)["']/gi) || [];
  linkMatches.forEach(link => {
    const hm = link.match(/href=["']([^"']+)["']/i);
    if (hm) {
      const href = hm[1];
      if (href.includes(domain) || href.startsWith('/') || href.startsWith('#') || href.startsWith('.')) analysis.details.links.internal++;
      else if (href.startsWith('http')) analysis.details.links.external++;
    }
  });

  // Detect No Content
  if (analysis.details.wordCount < 10) { analysis.verdict = 'NO_CONTENT'; analysis.confidence = 92; return analysis; }
  if (analysis.details.wordCount < 30 && analysis.details.headings.length === 0 && analysis.details.images === 0) { analysis.verdict = 'NO_CONTENT'; analysis.confidence = 80; return analysis; }
  if (analysis.details.wordCount > 30 && analysis.details.uniqueWordCount < 25) { analysis.verdict = 'NO_CONTENT'; analysis.confidence = 78; return analysis; }

  return analysis;
}

// === Single Analysis Endpoint ===
app.post('/api/analyze', async (req, res) => {
  const { domain: rawDomain } = req.body;
  if (!rawDomain || rawDomain.trim().length === 0) return res.status(400).json({ error: 'Domain is required' });

  const domain = normalizeDomain(rawDomain);
  try {
    const [dnsResults, sslResults, httpResults] = await Promise.all([analyzeDNS(domain), analyzeSSL(domain), analyzeHTTPStatus(domain)]);
    const { result: httpStatus, html } = httpResults;
    const contentAnalysis = analyzeContent(html, domain, httpStatus.finalUrl);

    let overallStatus = contentAnalysis.verdict === 'NO_CONTENT' ? 'NO_CONTENT' : 'ACTIVE';
    res.json({ domain, overallStatus, remark: contentAnalysis.verdict, notes: overallStatus === 'NO_CONTENT' ? 'no content' : 'valid', dns: dnsResults, ssl: sslResults, http: httpStatus, content: contentAnalysis });
  } catch (err) { res.status(500).json({ domain, error: err.message }); }
});

// === Bulk Endpoint ===
app.post('/api/analyze/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) return res.status(400).json({ error: 'Provide domains' });
  if (domains.length > 200) return res.status(400).json({ error: 'Max 200 domains' });

  const results = [];
  for (const rawDomain of domains) {
    try {
      const domain = normalizeDomain(rawDomain);
      const [dnsResults, sslResults, httpResults] = await Promise.all([analyzeDNS(domain), analyzeSSL(domain), analyzeHTTPStatus(domain)]);
      const { result: httpStatus, html } = httpResults;
      const contentAnalysis = analyzeContent(html, domain, httpStatus.finalUrl);

      let overallStatus = contentAnalysis.verdict === 'NO_CONTENT' ? 'NO_CONTENT' : 'ACTIVE';
      let notes = overallStatus === 'NO_CONTENT' ? 'no content' : 'valid';

      results.push({ domain, status: overallStatus, remark: contentAnalysis.verdict, notes });
    } catch (err) { results.push({ domain: normalizeDomain(rawDomain), status: 'ERROR', remark: 'ERROR', notes: err.message }); }
  }
  res.json({ total: results.length, results });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

app.listen(PORT, () => { console.log(`Server running on port ${PORT}`); });
