const crypto = require('crypto')
const { CURVES, Elliptic, Curve } = require('./elliptic.js')
const hash = require('./hash.js')
const hmac = require('./hmac.js')
const kdf = require('./kdf.js')
const mhf = require('./mhf.js')

function pbkdf2Sha256(password, salt, info) {
  const keyLen = 80
  const iterations = 100  // TODO: set from options with default
  var w0s_w1s = crypto.pbkdf2Sync(password, salt, iterations, keyLen, 'sha256');
  return w0s_w1s
}

/**
 * @typedef {object} CipherSuite
 * @property {Curve} curve An elliptic curve.
 * @property {Function} hash A hash function.
 * @property {Function} kdf A key derivation function.
 * @property {Function} mac A message authentication code function.
 * @property {Function} mhf A memory-hard hash function.
 */
function suiteEd25519Sha256HkdfHmacScrypt () {
  return {
    curve: new Elliptic(CURVES.ed25519),
    hash: hash.sha256,
    kdf: kdf.hkdfSha256,
    mac: hmac.hmacSha256,
    mhf: mhf.scrypt,
  }
}

/**
 * @typedef {object} CipherSuite
 * @property {Curve} curve An elliptic curve.
 * @property {Function} hash A hash function.
 * @property {Function} kdf A key derivation function.
 * @property {Function} mac A message authentication code function.
 * @property {Function} mhf A memory-hard hash function.
 */
function suiteP256Sha256HkdfHmac () {
  return {
    curve: new Elliptic(CURVES.p256),
    hash: hash.sha256,
    kdf: kdf.hkdfSha256,
    mac: hmac.hmacSha256,
    mhf: pbkdf2Sha256,
  }
}

/**
 * Enumerate the cipher suites.
 *
 * @readonly
 * @enum {CipherSuite}
 */
const cipherSuites = {
  'ED25519-SHA256-HKDF-HMAC-SCRYPT': suiteEd25519Sha256HkdfHmacScrypt,
  'P256-SHA256-HKDF-HMAC': suiteP256Sha256HkdfHmac
}

exports.cipherSuites = cipherSuites
