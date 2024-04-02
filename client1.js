const fetch = require('cross-fetch').fetch;
const crypto = require('crypto');
const fs = require('fs');


const HASH_ALGO = 'sha256';
const PORT = process.env.PORT || 3000;
const PRIVATE_KEY = importPrivateKey();


const message = process.argv[2];
makeHttpCall(message);

function importPrivateKey() {
  const privateKeyFile = fs.readFileSync('ClientPrivate.key', 'utf8');
  return crypto.createPrivateKey({
    key: privateKeyFile,
    format: 'pem',
    type: 'pkcs1'
  });
}

function importWrongPrivateKey() {
  const privateKeyFile = fs.readFileSync('Private1.key', 'utf8');
  return crypto.createPrivateKey({
    key: privateKeyFile,
    format: 'pem',
    type: 'pkcs1'
  });
}


async function makeHttpCall(message) {
  const body = JSON.stringify({ message });
  const signature = createSignature(body);
  const webhookUrl = `http://localhost:${PORT}/myhook`;
  const response = await fetch(webhookUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature': signature.toString('base64'),
    },
    body
  });

  console.log(`Response: ${await response.text()}`);
}

function createSignature(message) {
  return crypto.sign(HASH_ALGO, Buffer.from(message), {
    key: PRIVATE_KEY,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
}


