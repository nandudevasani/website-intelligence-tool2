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

function buildUrl(domain, protocol='https') {
  return `${protocol}://${domain}`;
}

function extractRootDomain(url) {
  try {
    let hostname = url.replace(/^https?:\/\//,'').replace(/^www\./,'').split('/')[0];
    const parts = hostname.split('.');
    if(parts.length>=2) return parts.slice(-2).join('.');
    return hostname;
  } catch { return ''; }
}

// --- DNS ---
async function analyzeDNS(domain){
  const res={hasA:false,error:null};
  try { const a = await dns.promises.resolve4(domain); res.hasA = a.length>0;} catch(e){res.error=e.message;}
  return res;
}

// --- SSL ---
function analyzeSSL(domain){
  return new Promise(resolve=>{
    const result={valid:false,error:null};
    try{
      const req = https.request({hostname:domain,port:443,method:'HEAD',timeout:8000,rejectUnauthorized:false}, (res)=>{
        const cert=res.socket.getPeerCertificate();
        if(cert && Object.keys(cert).length>0) result.valid=res.socket.authorized;
        resolve(result);
      });
      req.on('error',e=>{result.error=e.message;resolve(result);});
      req.on('timeout',()=>{result.error='Timeout';req.destroy();resolve(result);});
      req.end();
    }catch(e){result.error=e.message;resolve(result);}
  });
}

// --- HTTP ---
async function analyzeHTTP(domain){
  const result={isUp:false,statusCode:null,finalUrl:null,error:null};
  try{
    const res = await axios.get(buildUrl(domain), {timeout:15000,maxRedirects:10,validateStatus:()=>true});
    result.isUp=true;
    result.statusCode=res.status;
    result.finalUrl=res.request?.res?.responseUrl || res.config?.url || null;
    return {result,html:typeof res.data==='string'?res.data:''};
  }catch(err){
    try{
      const res = await axios.get(buildUrl(domain,'http'), {timeout:15000,maxRedirects:10,validateStatus:()=>true});
      result.isUp=true; result.statusCode=res.status;
      result.finalUrl=res.request?.res?.responseUrl || res.config?.url || null;
      return {result,html:typeof res.data==='string'?res.data:''};
    }catch(e){result.error=err.message;return {result,html:''};}
  }
}

// --- Content Analysis ---
function analyzeContent(html, domain, finalUrl){
  const analysis={verdict:'VALID',confidence:0,details:{}};
  if(!html || html.trim()===''){analysis.verdict='NO_CONTENT';return analysis;}
  let body=html.replace(/<script[\s\S]*?<\/script>/gi,'')
               .replace(/<style[\s\S]*?<\/style>/gi,'')
               .replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();
  const words=body.split(' ').filter(w=>w.length>1);
  const wordCount=words.length;
  analysis.details.wordCount=wordCount;

  // No content
  if(wordCount<30){analysis.verdict='NO_CONTENT';return analysis;}

  // Political campaign
  if(/vote|campaign|elect/i.test(html) || /vote\d*/i.test(domain)){analysis.verdict='POLITICAL_CAMPAIGN';return analysis;}

  return analysis;
}

// --- Bulk Endpoint ---
app.post('/api/analyze/bulk', async (req,res)=>{
  const {domains}=req.body;
  if(!domains || !Array.isArray(domains) || domains.length===0) return res.status(400).json({error:'Provide domains'});
  if(domains.length>200) return res.status(400).json({error:'Max 200 domains'});

  const results=[];
  for(const rawDomain of domains){
    try{
      const domain=normalizeDomain(rawDomain);
      const [dnsRes,sslRes,httpRes]=await Promise.all([analyzeDNS(domain),analyzeSSL(domain),analyzeHTTP(domain)]);
      const {result: httpStatus, html}=httpRes;
      const content=analyzeContent(html, domain, httpStatus.finalUrl);

      let status='ACTIVE';
      let notes='valid';
      if(!httpStatus.isUp || !dnsRes.hasA) status='DOWN';
      if(content.verdict==='NO_CONTENT'){status='NO_CONTENT';notes='no content';}
      if(content.verdict==='POLITICAL_CAMPAIGN'){status='POLITICAL_CAMPAIGN';notes='political site';}

      results.push({domain,status,remark:content.verdict,notes});
    }catch(err){
      results.push({domain:normalizeDomain(rawDomain),status:'ERROR',remark:'ERROR',notes:err.message});
    }
  }
  res.json({total:results.length,results});
});

app.get('/api/health',(req,res)=>res.json({status:'ok'}));
app.listen(PORT,()=>{console.log(`Server running on port ${PORT}`);});
