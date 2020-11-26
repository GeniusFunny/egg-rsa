'use strict';

const fs = require('fs');
const path = require('path');
const {
  publicEncrypt,
  privateDecrypt,
  createVerify,
  createSign,
} = require('crypto');

class RSAObject {
  constructor(config) {
    if (config.publicKeyValue || config.publicKeyPem) {
      this.pubKey =
        config.publicKeyValue ||
        fs.readFileSync(path.join(__dirname, config.publicKeyPem)).toString();
    }
    if (config.privateKeyValue || config.privateKeyPem) {
      this.prvKey =
        config.privateKeyValue ||
        fs.readFileSync(path.join(__dirname, config.privateKeyPem)).toString();
    }
    this.config(config.options);
  }
  config(options = {}) {
    this.MAX_DECRYPT_BLOCK = options.maxDecryptBlock || RSAObject.MAX_DECRYPT_BLOCK;
    this.MAX_ENCRYPT_BLOCK = options.maxEncryptBlock || RSAObject.MAX_ENCRYPT_BLOCK;
    this.CHARSET = options.charset || RSAObject.CHARSET;
    this.SIGN_ALG = options.signAlg || RSAObject.SIGN_ALG;
  }
  sign(data) {
    const dataBuffer = Buffer.from(data, this.CHARSET);
    try {
      const signer = createSign(this.SIGN_ALG);
      signer.update(dataBuffer);
      signer.end();
      return signer.sign(this.prvKey, 'base64');
    } catch (error) {
      console.log(error);
    }
  }
  verify(data, signature) {
    const dataBuffer = Buffer.from(data, this.CHARSET);
    const signatureBuffer = Buffer.from(signature, 'base64');
    try {
      const verifier = createVerify(this.SIGN_ALG);
      verifier.update(dataBuffer);
      verifier.end();
      const result = verifier.verify(this.pubKey, signatureBuffer);
      return result;
    } catch (error) {
      console.log(error);
    }
  }
  decrypt(strData) {
    const bytes = Buffer.from(strData, 'base64');
    try {
      let index = 0;
      const bufs = [];
      const dataLength = bytes.length;
      if (dataLength > this.MAX_DECRYPT_BLOCK) {
        while (index < dataLength) {
          if (index + this.MAX_DECRYPT_BLOCK < dataLength) {
            bufs.push(
              privateDecrypt(
                {
                  key: this.prvKey,
                },
                bytes.slice(index, index + this.MAX_DECRYPT_BLOCK)
              )
            );
            index += this.MAX_DECRYPT_BLOCK;
          } else {
            bufs.push(
              privateDecrypt(
                {
                  key: this.prvKey,
                },
                bytes.slice(index, dataLength)
              )
            );
            index = dataLength;
          }
        }
      } else {
        bufs.push(
          privateDecrypt(
            {
              key: this.prvKey,
            },
            bytes
          )
        );
      }
      const result = Buffer.concat(bufs).toString();
      return result;
    } catch (error) {
      console.log(error);
    }
  }
  encrypt(pladat) {
    const bytes = Buffer.from(pladat, this.CHARSET);
    try {
      let index = 0;
      const bufs = [];
      const dataLength = bytes.length;
      if (dataLength > this.MAX_ENCRYPT_BLOCK) {
        while (index < dataLength) {
          if (index + this.MAX_ENCRYPT_BLOCK < dataLength) {
            bufs.push(
              publicEncrypt(
                {
                  key: this.pubKey,
                },
                bytes.slice(index, index + this.MAX_ENCRYPT_BLOCK)
              )
            );
            index += this.MAX_ENCRYPT_BLOCK;
          } else {
            bufs.push(
              publicEncrypt(
                {
                  key: this.pubKey,
                },
                bytes.slice(index, dataLength)
              )
            );
            index = dataLength;
          }
        }
      } else {
        bufs.push(
          publicEncrypt(
            {
              key: this.pubKey,
            },
            bytes
          )
        );
      }
      const result = Buffer.concat(bufs).toString('base64');
      return result;
    } catch (error) {
      console.log(error);
    }
  }
}

RSAObject.MAX_ENCRYPT_BLOCK = 200;
RSAObject.MAX_DECRYPT_BLOCK = 256;
RSAObject.CHARSET = 'utf-8';
RSAObject.SIGN_ALG = 'SHA256';
RSAObject.isPublicKey = key => {
  return !!key;
};
RSAObject.isPrivateKey = key => {
  return !!key;
};

module.exports = (config, app) => {
  if (!RSAObject.isPublicKey(config.publicKeyValue) && !RSAObject.isPrivateKey(config.privateKeyValue)) {
    throw new Error('publicKeyValue or privateKeyValue is not correct');
  }
  // 创建实例
  const client = new RSAObject(config);

  // 做启动应用前的检查
  app.beforeStart(async () => {
    app.coreLogger.info('[egg-rsa] init instance success');
  });
  return client;
};
