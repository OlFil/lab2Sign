const crypto = require('crypto');
const fs = require('fs');

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  
  fs.writeFileSync("ServerPublic.key", publicKey.export({type: 'pkcs1', format: 'pem'}));
  fs.writeFileSync("ServerPrivate.key", privateKey.export({type: 'pkcs1', format: 'pem'}));