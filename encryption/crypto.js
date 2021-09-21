const crypto = require('crypto');


// supported hashes
// console.log(crypto.getHashes());
// console.log(crypto.getCiphers());


// random bytes
// crypto.randomBytes(16, (err, buf) => {
//     console.log(buf.toString('hex'));
// });

let iv = crypto.randomBytes(16);


// create hash
let hash = crypto
    .createHash('sha1')
    .update('your message')
    .digest('hex');

console.log(hash);


// aes 256-bit cipher block chaining (cbc) encryption/decryption
let secret_message = 'Hey this is a test';
let key = '12345678123456781234567812345678';

let cipher = crypto.createCipheriv('aes256', key, iv);
let encrypted = cipher.update(secret_message, 'utf-8', 'hex');
encrypted += cipher.final('hex');

console.log('encrypted AES: ' + encrypted)




// The `generateKeyPairSync` method accepts two arguments:
// 1. The type ok keys we want, which in this case is "rsa"
// 2. An object with the properties of the key
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    // The standard secure default length for RSA keys is 2048 bits
    modulusLength: 2048,
});

const data = encrypted;

const encryptedData = crypto.publicEncrypt(
    {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    },
    // We convert the data string to a buffer using `Buffer.from`
    Buffer.from(data)
);

// The encrypted data is in the form of bytes, so we print it in base64 format
// so that it's displayed in a more readable form
console.log("encypted data RSA: ", encryptedData.toString("base64"));

const decryptedData = crypto.privateDecrypt(
    {
        key: privateKey,
        // In order to decrypt the data, we need to specify the
        // same hashing function and padding scheme that we used to
        // encrypt the data in the previous step
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    },
    encryptedData
);

// The decrypted data is of the Buffer type, which we can convert to a
// string to reveal the original data
console.log("decrypted data RSA: ", decryptedData.toString());

let decipher = crypto.createDecipheriv('aes256', key, iv);
let decrypted = decipher.update(encrypted, 'hex', 'utf-8');
decrypted += decipher.final('utf-8');

console.log('decrypted AES: ' + decrypted)