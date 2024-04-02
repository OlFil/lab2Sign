const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

const HASH_ALGO = 'sha256';
const PORT = process.env.PORT || 3000;
const PUBLIC_KEY = importPublicKey();

const SERVER_PRIVATE_KEY=importPrivateKeyServer();
const SERVER_PUBLIC_KEY=importPublicKeyServer();


const app = express();
app.use(express.json());


app.post('/myhook', (req, res) => {
  const signature = req.get('X-Signature');
  const body = req.body;
  
  const isVerified = crypto.verify(
    HASH_ALGO,
    Buffer.from(JSON.stringify(body)),
    {
      key: PUBLIC_KEY,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    Buffer.from(signature, 'base64')
  );

  if (isVerified) {
    res.send(`Received verified message: ${body.message}`);
  } else {
    res.send('Unable to verify signature');
  }
});


app.listen(PORT, () => console.log(`Listening on port ${PORT}`));

function importPublicKey() {
  const publicKeyFile = fs.readFileSync('ClientPublic.key', 'utf8');
  return crypto.createPublicKey({
    key: publicKeyFile,
    format: 'pem',
    type: 'pkcs1'
  });
}

function makeid(length) {
  const characters =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  let result = '';

  // Create an array of 32-bit unsigned integers
  const randomValues = new Uint32Array(length);
  
  // Generate random values
  crypto.getRandomValues(randomValues);
  randomValues.forEach((value) => {
    result += characters.charAt(value % charactersLength);
  });
  return result;
}

function importPrivateKeyServer() {
  const privateKeyFile = fs.readFileSync('ServerPrivate.key', 'utf8');
  return crypto.createPrivateKey({
    key: privateKeyFile,
    format: 'pem',
    type: 'pkcs1'
  });
}

function importPublicKeyServer() {
  const publicKeyFile = fs.readFileSync('ServerPublic.key', 'utf8');
  return crypto.createPublicKey({
    key: publicKeyFile,
    format: 'pem',
    type: 'pkcs1'
  });
}

function createSignature(message) {
  return crypto.sign(HASH_ALGO, Buffer.from(message), {
    key: SERVER_PRIVATE_KEY,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
}

app.get('/serverkey', (req, res) => {
  res.set('Content-Type', 'application/json')
  let publicKey = fs.readFileSync('ServerPublic.key', 'utf8');
  const data = {
    "public_key":publicKey
  }
  res.send(data);
});

app.get('/servermessage', (req, res) => {
  let message = makeid(7);
  const ServerSignature = createSignature(message);
  res.set('Content-Type', 'application/json');
  res.set('X-Signature', ServerSignature.toString('base64'))
  const cryptoMes = {
    "message":message
  }
  res.send(cryptoMes);
});
