// Dependencies
const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
dotenv.config();
const app = express().use(bodyParser.json()); // creates http server

// Globals
const VERIFF_API_TOKEN = process.env.VERIFF_API_TOKEN;
const VERIFF_API_SECRET = process.env.VERIFF_API_SECRET;

if (!VERIFF_API_TOKEN) throw('VERIFF_API_TOKEN environment variable is required');
if (!VERIFF_API_SECRET) throw('VERIFF_API_SECRET environment variable is required');

// app.get('/', (req, res) => {
//     // check if verification token is correct
//     // if (req.query.token !== token) {
//     //     return res.sendStatus(401);
//     // }
//
//     // return challenge
//     return res.end(req.query.challenge);
// });
function isSignatureValid(data) {
    const {signature, secret} = data;
    let {payload} = data;

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
    const secret = VERIFF_API_SECRET;
    const payload = req.body;
    console.log('Received a webhook');
    console.log('Validated signature:', isSignatureValid({signature, secret, payload}));
    console.log(req.body);

    if (!isSignatureValid({signature, secret, payload})) {
        res.status(401).json({
            status_code: 401,
            message: 'Unauthorized'
        });
    } else {
        res.status(200).json({
            status_code: 200,
            data: {
                verificationId: verificationId
            }
        });
    }
});

// Decision
app.post('/test/notification', (req, res) => {
    const signature = req.get('x-signature');
    const secret = VERIFF_API_SECRET;
    const payload = req.body;
    console.log('Received a webhook');
    console.log('Validated signature:', isSignatureValid({signature, secret, payload}));
    console.log(req.body);

    if (!isSignatureValid({signature, secret, payload})) {
        res.status(401).json({
            status_code: 401,
            message: 'Unauthorized'
        });
    } else {
        res.status(200).json({
            status_code: 200,
            data: {
                verificationId: req.body.verification.id,
                verificationStatus: req.body.verification.status,
                reason: req.body.verification.reason,
            }
        });
    }
});

let port = process.env.PORT || 5000;
app.listen(port, () => console.log('Veriff Webhook is listening on port: ' + port));