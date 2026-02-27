import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeDomain } from './analyzer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/analyze/bulk', async (req, res) => {
    const { domains } = req.body;
    if (!domains || !Array.isArray(domains)) {
        return res.status(400).json({ error: 'Please provide an array of domains.' });
    }

    const results = [];
    for (const rawDomain of domains) {
        const result = await analyzeDomain(rawDomain.trim());
        results.push(result);
    }
    res.json(results);
});

app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});
