import axios from 'axios';
import dns from 'dns';

export async function analyzeDomain(domain) {
    let result = { domain, status: 'PENDING', remark: '', notes: '' };

    try {
        // 1. Connectivity Check
        const addresses = await dns.promises.resolve4(domain).catch(() => null);
        if (!addresses) {
            return { ...result, status: 'DOWN', remark: 'DOWN', notes: 'Domain not found' };
        }

        // 2. Fetch with Redirect Following
        const response = await axios.get(`http://${domain}`, { 
            timeout: 10000, 
            validateStatus: () => true,
            maxRedirects: 5 
        });

        // 3. SMART REDIRECT CHECK
        const finalUrl = new URL(response.request.res.responseUrl);
        const finalHostname = finalUrl.hostname.replace('www.', '');
        if (!finalHostname.includes(domain.toLowerCase())) {
            return { 
                ...result, 
                status: 'REDIRECTED', 
                remark: 'REDIRECTED', 
                notes: `Lands on ${finalHostname}` 
            };
        }

        // 4. CLEAN CONTENT CHECK (Removing scripts/styles noise)
        let html = response.data.toString();
        // Strip out <script> and <style> tags and their contents entirely
        const cleanText = html
            .replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gmi, ' ')
            .replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gmi, ' ')
            .replace(/<[^>]*>?/gm, ' ') // Strip remaining tags
            .replace(/\s+/g, ' ') // Collapse whitespace
            .trim();

        const words = cleanText.split(' ').filter(w => w.length > 1);
        const lowerText = cleanText.toLowerCase();

        // 5. Placeholder Detection
        const comingSoonPatterns = [/coming soon/i, /under construction/i, /launching soon/i, /domain for sale/i];
        if (comingSoonPatterns.some(p => p.test(lowerText))) {
            return { ...result, status: 'COMING_SOON', remark: 'COMING_SOON', notes: 'Placeholder/Parked' };
        }

        // 6. Content Substance Logic
        if (words.length < 50) {
            return { ...result, status: 'NO_CONTENT', remark: 'NO_CONTENT', notes: `Very little text (${words.length} words)` };
        }

        return { ...result, status: 'ACTIVE', remark: 'ACTIVE', notes: 'Genuine content found' };

    } catch (error) {
        return { ...result, status: 'DOWN', remark: 'DOWN', notes: 'Connection failed' };
    }
}
