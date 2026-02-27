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
    if (!domains || !Array.isArray(domains)) return res.status(400).send('Invalid input');

    const results = [];
    for (const domain of domains) {
        results.push(await analyzeDomain(domain.trim()));
    }
    res.json(results);
});

app.listen(PORT, () => console.log(`🚀 System Live: http://localhost:${PORT}`));
