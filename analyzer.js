import axios from 'axios';
import dns from 'dns';

export async function analyzeDomain(domain) {
    let result = { domain, status: 'PENDING', remark: '', notes: '' };

    try {
        const addresses = await dns.promises.resolve4(domain).catch(() => null);
        if (!addresses) {
            return { ...result, status: 'DOWN', remark: 'DOWN', notes: 'Site not reachable' };
        }

        const response = await axios.get(`http://${domain}`, { 
            timeout: 8000, 
            validateStatus: () => true 
        });

        const html = response.data.toString().toLowerCase();

        // Check for Coming Soon
        const comingSoonPatterns = [/coming soon/i, /under construction/i, /launching soon/i];
        if (comingSoonPatterns.some(p => p.test(html))) {
            return { ...result, status: 'COMING_SOON', remark: 'COMING_SOON', notes: 'Placeholder page' };
        }

        // Check for Content Substance
        const words = html.replace(/<[^>]*>?/gm, ' ').split(/\s+/).filter(w => w.length > 1);
        if (words.length < 50) {
            return { ...result, status: 'NO_CONTENT', remark: 'NO_CONTENT', notes: 'Thin content' };
        }

        return { ...result, status: 'ACTIVE', remark: 'ACTIVE', notes: 'Valid site with content' };

    } catch (error) {
        return { ...result, status: 'DOWN', remark: 'DOWN', notes: 'Connection failed' };
    }
}
