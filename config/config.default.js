'use strict';

/**
 * egg-rsa default config
 * @member Config#rsa
 * @property {String} SOME_KEY - some description
 */
exports.rsa = {
  MAX_DECRYPT_BLOCK: 256,
  MAX_ENCRYPT_BLOCK: 200,
  CHARSET: 'utf-8',
  SIGN_ALG: 'SHA256',
  enable: true,
};
