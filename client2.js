const fetch = require('cross-fetch').fetch;
const crypto = require('crypto');
const fs = require('fs');

const HASH_ALGO = 'sha256';
const PORT = process.env.PORT || 3000;


async function makeHttpCall() {
    const webhookUrlKey = `http://localhost:${PORT}/serverkey`;
    const webhookUrlMes = `http://localhost:${PORT}/servermessage`;
    let serverKeyResponse = await fetch(webhookUrlKey,
      {
        headers: {
          'Accept': 'application/json'
        }
      });
    let serverKeyData = await serverKeyResponse.json();
    

    const serverPublicKey = crypto.createPublicKey({
      key: serverKeyData['public_key'],
      format: 'pem',
      type: 'pkcs1'
    });
    const serverMessageResponse = await fetch(webhookUrlMes, {
      method: 'GET'
    });
    let serverMessageData = await serverMessageResponse.json();

    const signature = serverMessageResponse.headers.get('X-Signature');

    const isVerified = crypto.verify(
      HASH_ALGO,
      Buffer.from(serverMessageData["message"]),
      {
        key: serverPublicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      },
      Buffer.from(signature, 'base64')
    );

    if (isVerified) {
      console.log(`Received verified message: ${serverMessageData["message"]}`);
    } else {
      console.log('Unable to verify signature');
    }
    
  }


  makeHttpCall();