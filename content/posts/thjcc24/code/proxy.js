const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

function CheckIfHttp(scheme) {
    return scheme.startsWith('http://');
}

app.get('/fetch', (req, res) => {
    const scheme = req.query.scheme;
    const host = req.query.host;
    const path = req.query.path;
    if (!scheme || !host || !path) {
        return res.status(400).send('Missing parameters');
    }
    const client = scheme.startsWith('https') ? https : http;
    const fixedhost = host + '.cggc.chummy.tw'; // oops, I forgot to change it

    if (CheckIfHttp(scheme)) {
        return res.send('Sorry, Only accepts https'); // pls no http :(
    }

    const url = scheme + fixedhost + path;
    console.log('[+] Fetching :', url);
    client.get(url, (response) => {
        let data = '';

        response.on('data', (chunk) => {
            data += chunk;
        });

        response.on('end', () => {
            res.send(data);
        });
    }).on('error', (err) => {
        console.error('Error: ', err.message);
        res.status(500).send('Failed to fetch data from the URL');
    });
});

app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on http://0.0.0.0:3000');
});