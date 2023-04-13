const jsonfile = require('jsonfile');
const forge = require('node-forge');
const write = require('write');
const readfile = require("read-file");
const read = require("read");
const fs = require('fs');
const { base64encode, base64decode } = require('nodejs-base64');
const { Synchronized }  = require("node-synchronized");
const winston = require('winston');

var logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    transports: [
      new winston.transports.Console({'timestamp': true}),
    ],
});

exports.setLogger = function(_logger){
    logger = _logger;
}

const block = new Synchronized();
const pki = forge.pki;

const keystore_filename = "keystore/keystore";
const publickey_filename = "keystore/publickey";
const privatekey_filename = "keystore/privatekey";
const keyEncryptionKey_filename = "keystore/keyEncryptionKey.secret";

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
    logger.verbose("createKeypair()");
    const keypair = pki.rsa.generateKeyPair();
    const keyEncryptionKey = forge.random.getBytesSync(32);
    
    const publicPem = pki.publicKeyToPem(keypair.publicKey);
    const encryptedPrivatePem = pki.encryptRsaPrivateKey(keypair.privateKey, keyEncryptionKey, {algorithm: 'aes256'});
    const keyEncryptionKeyBase64 = base64encode(keyEncryptionKey);

    logger.info("Write new Keys to file");
    write.sync(publickey_filename, publicPem);
    write.sync(privatekey_filename, encryptedPrivatePem);
    write.sync(keyEncryptionKey_filename, keyEncryptionKeyBase64);
    logger.warn("generated new keypairs and wrote them to the files. Please consider securing the keyEncryptionKey.secret at another place, so no intruder can decrypt the passwords");
}

function insertPassword(username, password){
    logger.verbose("insertPassword(${username}, ...)");
    block.Synchronized(first => {
        logger.debug("read publickey from file");
        const publicKey = pki.publicKeyFromPem(readfile.sync(publickey_filename, 'utf8'));

        var keystore;
        if(fs.existsSync(keystore_filename)){
            logger.debug("read keystore file");
            keystore = jsonfile.readFileSync(keystore_filename, 'utf8');
        } else {
            logger.debug("no keystore file found");
            createKeypair();
            keystore = {};
        }
        
        keystore[username] = base64encode(publicKey.encrypt(password));
        logger.debug("write keystore to file");
        jsonfile.writeFileSync(keystore_filename, keystore, { spaces: 2, EOL: '\r\n' });
    });
 }

async function getPassword(username){
    logger.verbose("getPassword(${username}, ...)");

    var keyEncryptionKeyBase64;
    if(fs.existsSync(keystore_filename)){
        logger.debug("read key encryption key from file");
        keyEncryptionKeyBase64 = readfile.sync(keyEncryptionKey_filename, 'utf8');
    } else {
        logger.debug("read key encryption key from user input");
        try {
            const result = await read({
                "prompt": "no keyEncryptionKey File found, please enter the key in base64-format here:",
                "silent": true,
                "timeout": 30 * 1000,
            }, (input) => {
                keyEncryptionKeyBase64 = input;
            })
        } catch (er) {
            logger.error(er);
            logger.error("cannot get Password");
            return;
        }
    }

    logger.debug("read encrypted private key from file");
    const encryptedPrivatePem = readfile.sync(privatekey_filename, 'utf8');
    const privateKey = pki.decryptRsaPrivateKey(encryptedPrivatePem, base64decode(keyEncryptionKeyBase64));

    block.Synchronized(first => {
        logger.debug("read keystore from file");
        const keystore = jsonfile.readFileSync(keystore_filename, 'utf8');
    });
    logger.debug("return password from keystore");
    return privateKey.decrypt(base64decode(keystore[username]));
}