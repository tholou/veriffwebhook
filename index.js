// Dependencies
const fs = require('fs');
const crypto = require('crypto');
const fetch = require('node-fetch');
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv'); dotenv.config();
const app = express().use(bodyParser.json()); // creates http server

// Globals
const API_TOKEN = process.env.API_TOKEN;
const API_SECRET = process.env.API_SECRET;

if (!API_TOKEN) throw('API_TOKEN environment variable is required');
if (!API_SECRET) throw('API_SECRET environment variable is required');

// app.get('/', (req, res) => {
//     // check if verification token is correct
//     // if (req.query.token !== token) {
//     //     return res.sendStatus(401);
//     // }
//
//     // return challenge
//     return res.end(req.query.challenge);
// });

function generateSignature(payload, secret) {
    if (payload.constructor === Object) {
        payload = JSON.stringify(payload);
    }

    if (payload.constructor !== Buffer) {
        payload = Buffer.from(payload, 'utf8');
    }

    const signature = crypto.createHash('sha256');
    signature.update(payload);
    signature.update(new Buffer.from(secret, 'utf8'));
    return signature.digest('hex');
}

function isSignatureValid(data) {
    const { signature, secret } = data;
    let { payload } = data;

    if (data.payload.constructor === Object) {
        payload = JSON.stringify(data.payload);
    }
    if (payload.constructor !== Buffer) {
        payload = new Buffer.from(payload, 'utf8');
    }
    const hash = crypto.createHash('sha256');
    hash.update(payload);
    hash.update(new Buffer.from(secret));
    const digest = hash.digest('hex');
    return digest === signature.toLowerCase();
}

app.post('/test/hook', (req, res) => {
    const signature = req.get('x-signature');
    const secret = API_SECRET;
    const payload = req.body;


    console.log('Received a webhook');
    console.log('Generate signature:', generateSignature(payload, API_SECRET));
    console.log('Validated signature:', isSignatureValid({ signature, secret, payload }));
    // check if verification token is correct
    // if (req.query.token !== token) {
    //     return res.sendStatus(401);
    // }

    // print request body
    console.log(req.body);

    // return a text response
    const data = {
        responses: [
            {
                type: 'text',
                elements: ['Hi', 'Hello']
            }
        ]
    };

    res.json(data);
});

app.post('/test/notification', (req, res) => {
    const signature = req.get('x-signature');
    const secret = API_SECRET;
    const payload = req.body;


    console.log('Received a webhook');
    console.log('Generate signature:', generateSignature(payload, API_SECRET));
    console.log('Validated signature:', isSignatureValid({ signature, secret, payload }));
    // check if verification token is correct
    // if (req.query.token !== token) {
    //     return res.sendStatus(401);
    // }

    // print request body
    console.log(req.body);

    // return a text response
    const data = {
        responses: [
            {
                type: 'text',
                elements: ['Hi', 'Hello']
            }
        ]
    };

    res.json(data);
});

var port = process.env.PORT || 5000;
app.listen(port , () => console.log('[Veriff] Webhook is listening on port: ' + port));