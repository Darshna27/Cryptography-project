const crypto = require('crypto');

// AES encryption function
function aesEncrypt(key, iv, buffer) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted;
}

// AES decryption function
function aesDecrypt(key, iv, buffer) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(buffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}

// Function to pad or trim key to 32 bytes
function formatKey(key) {
    let keyBuffer = Buffer.from(key, 'utf-8');
    if (keyBuffer.length < 32) {
        keyBuffer = Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)], 32);
    } else if (keyBuffer.length > 32) {
        keyBuffer = keyBuffer.slice(0, 32);
    }
    return keyBuffer;
}

module.exports = { aesEncrypt, aesDecrypt, formatKey };
