// Dependencies
const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
dotenv.config();
const app = express().use(bodyParser.json()); // creates http server

// Globals
const VERIFF_API_TOKEN = process.env.VERIFF_API_TOKEN;
const VERIFF_API_SECRET = process.env.VERIFF_API_SECRET;
const EMAIL_USERNAME = process.env.EMAIL_USERNAME;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;

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

function sendEmail(verifiationID, verificationStatus, reason) {
    // Create the transporter with the required configuration for Outlook
    // change the user and pass !
    let transporter = nodemailer.createTransport({
        host: "smtp-mail.outlook.com", // hostname
        secureConnection: false, // TLS requires secureConnection to be false
        port: 587, // port for secure SMTP
        tls: {
            ciphers:'SSLv3'
        },
        auth: {
            user: EMAIL_USERNAME,
            pass: EMAIL_PASSWORD
        }
    });

    if (reason == null) {
        reason = 'ID was valid';
    }

    // setup e-mail data, even with unicode symbols
    let mailOptions = {
        from: '"Veriff WebHook " <tholou4reel@outlook.com>', // sender address (who sends)
        to: 'tholou4reel@outlook.com', // list of receivers (who receives)
        subject: 'Veriff: New Notification Received', // Subject line
        html: '<b>Hello!</b><br> ' +
        '<p><b>Verification ID: </b>' + verifiationID + '</p>' +
        '<p><b>Verification Status: </b>' + verificationStatus.charAt(0).toUpperCase() + verificationStatus.substring(1) + '</p>' +
        '<p><b>Verification Reason: </b>' + reason
    };

    // send mail with defined transport object
    transporter.sendMail(mailOptions, function(error, info){
        if(error){
            return console.log(error);
        }

        console.log('Message sent: ' + info.response);
    });

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
            response_from_veriff: {
                id: req.body.id,
                feature: req.body.feature,
                code: req.body.code,
                action: req.body.action
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
        sendEmail(req.body.verification.id, req.body.verification.status, req.body.verification.reason);
        res.status(200).json({
            status_code: 200,
            response_from_veriff: {
                verificationId: req.body.verification.id,
                verificationStatus: req.body.verification.status,
                reason: req.body.verification.reason,
            }
        });
    }
});

let port = process.env.PORT || 5000;
app.listen(port, () => console.log('Veriff Webhook is listening on port: ' + port));