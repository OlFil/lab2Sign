const crypto = require('crypto');
const fs = require('fs');


let keys = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const publicKeyC = keys.publicKey;
const privateKeyC = keys.privateKey;

let wrongKeys = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
let wrongPrivateKey= wrongKeys.privateKey;

fs.writeFileSync("ClientPublic.key", publicKeyC.export({type: 'pkcs1', format: 'pem'}));
fs.writeFileSync("ClientPrivate.key", privateKeyC.export({type: 'pkcs1', format: 'pem'}));
fs.writeFileSync("Private1.key", wrongPrivateKey.export({type: 'pkcs1', format: 'pem'}));
