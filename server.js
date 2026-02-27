import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeDomain } from './analyzer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Middleware to handle JSON data and serve your HTML/CSS files
app.use(express.json());
app.use(express.static(__dirname)); 

// === THE BULK ANALYSIS ROUTE ===
app.post('/api/analyze/bulk', async (req, res) => {
    const { domains } = req.body; // This is the "Stack" of domains from the user
    
    if (!domains || !Array.isArray(domains)) {
        return res.status(400).json({ error: 'Please provide an array of domains.' });
    }

    console.log(`Starting analysis for ${domains.length} domains...`);

    const results = [];

    // We process the domains one by one to ensure accuracy
    for (const rawDomain of domains) {
        const result = await analyzeDomain(rawDomain.trim());
        results.push(result);
    }

    res.json(results);
});

app.listen(PORT, () => {
    console.log(`🚀 Server is running at http://localhost:${PORT}`);
});
