const jsonfile = require('jsonfile');
const forge = require('node-forge');
const write = require('write');
const readfile = require("read-file");
const fs = require('fs');
const { base64encode, base64decode } = require('nodejs-base64');
const { Synchronized }  = require("node-synchronized");

const block = new Synchronized();
const pki = forge.pki;

const keystore_filename = "keystore.secret";
const publickey_filename = "publickey.secret";
const privatekey_filename = "privatekey.secret";
const keyEncryptionKey_filename = "keyEncryptionKey.secret";

exports.setKeystoreFilename = function(keystore_filename){
    global.keystore_filename = keystore_filename;
}

exports.setPublickeyFilename = function(publickey_filename){
    global.publickey_filename = publickey_filename;
}

exports.setPrivateKeyFilename = function(privatekey_filename){
    global.privatekey_filename = privatekey_filename;
}

exports.setKeyEncryptionKeyFilename = function(keyEncryptionKey_filename){
    global.keyEncryptionKey_filename = keyEncryptionKey_filename;
}

exports.createKeypair = function(){
    createKeypair();
}

exports.insertPassword = function(username, password){
    insertPassword(username, password);
}

exports.getPassword = function(username){
    getPassword(username);
}

function createKeypair(){
    const keypair = pki.rsa.generateKeyPair();
    const keyEncryptionKey = forge.random.getBytesSync(32);
    
    const publicPem = pki.publicKeyToPem(keypair.publicKey);
    const encryptedPrivatePem = pki.encryptRsaPrivateKey(keypair.privateKey, keyEncryptionKey, {algorithm: 'aes256'});
    const keyEncryptionKeyBase64 = base64encode(keyEncryptionKey);

    write.sync(publickey_filename, publicPem);
    write.sync(privatekey_filename, encryptedPrivatePem);
    write.sync(keyEncryptionKey_filename, keyEncryptionKeyBase64);
    console.log("generated new keypairs and wrote them to the files. Please consider securing the keyEncryptionKey.secret at another place, so no intruder can decrypt the passwords");
}

function insertPassword(username, password){
    block.Synchronized(first => {
        const publicKey = pki.publicKeyFromPem(readfile.sync(publickey_filename, 'utf8'));

        var keystore;
        if(fs.existsSync(keystore_filename)){
            keystore = jsonfile.readFileSync(keystore_filename, 'utf8');
        } else {
            createKeypair();
            keystore = {};
        }
        
        keystore[username] = base64encode(publicKey.encrypt(password));
        jsonfile.writeFileSync(keystore_filename, keystore, { spaces: 2, EOL: '\r\n' });
    });
 }

async function getPassword(username){
    var keyEncryptionKeyBase64;
    if(fs.existsSync(keystore_filename)){
        keyEncryptionKeyBase64 = readfile.sync(keyEncryptionKey_filename, 'utf8');
    } else {
        try {
            const result = await read({
                "prompt": "no keyEncryptionKey File found, please enter the key in base64-format here:",
                "silent": true,
                "timeout": 30 * 1000,
            }, (input) => {
                keyEncryptionKeyBase64 = input;
            })
        } catch (er) {
            console.error(er);
            console.error("cannot get Password");
            return;
        }
    }

    const encryptedPrivatePem = readfile.sync(privatekey_filename, 'utf8');
    const privateKey = pki.decryptRsaPrivateKey(encryptedPrivatePem, base64decode(keyEncryptionKeyBase64));

    block.Synchronized(first => {
        const keystore = jsonfile.readFileSync(keystore_filename, 'utf8');
    });
    return privateKey.decrypt(base64decode(keystore[username]));
}