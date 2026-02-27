import axios from 'axios';
import dns from 'dns';

/**
 * Logic Engine: Checks if a domain is active, redirected, or a placeholder.
 */
export async function analyzeDomain(domain) {
    let result = { domain, status: 'PENDING', remark: '', notes: '' };

    try {
        // 1. DNS Check: Does the domain exist?
        const addresses = await dns.promises.resolve4(domain).catch(() => null);
        if (!addresses) {
            return { ...result, status: 'DOWN', remark: 'DOWN', notes: 'site not reachable' };
        }

        // 2. Visit the Site
        const response = await axios.get(`http://${domain}`, { 
            timeout: 10000, 
            validateStatus: () => true 
        });

        const html = response.data.toString().toLowerCase();

        // 3. Keyword Check: Is it "Coming Soon"?
        const comingSoonPatterns = [/coming soon/i, /under construction/i, /launching soon/i];
        if (comingSoonPatterns.some(p => p.test(html))) {
            return { ...result, status: 'COMING_SOON', remark: 'COMING_SOON', notes: 'placeholder page' };
        }

        // 4. Substance Check: Word Count
        const words = html.replace(/<[^>]*>?/gm, ' ').split(/\s+/).filter(w => w.length > 1);
        if (words.length < 50) {
            return { ...result, status: 'NO_CONTENT', remark: 'NO_CONTENT', notes: 'no content website' };
        }

        return { ...result, status: 'ACTIVE', remark: 'ACTIVE', notes: 'valid site with content' };

    } catch (error) {
        return { ...result, status: 'DOWN', remark: 'DOWN', notes: 'connection failed' };
    }
}
