const BN = require('bn.js')
const EC = require('elliptic').ec

const TWO_POW_255 = new BN(2).pow(new BN(255))

/**
 * @typedef {object} Curve
 * @property {string} name The number of the curve.
 * @property {BN} p The order of the subgroup G with a generator P, where P is a point specified by the curve.
 * @property {BN} h The cofactor of the subgroup G.
 * @property {string} M SEC1-compressed coordinate of M.
 * @property {string} N SEC1-compressed coordinate of N.
 */
const curveEd25519 = {
  name: 'ed25519',
  // It is defined in [draft-irtf-cfrg-spake2-08] that
  M: 'd048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf',
  N: 'd3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab',
  p: new BN('7237005577332262213973186563042994240857116359379907606001950938285454250989', 10),
  h: new BN(8)
}

/**
 * @typedef {object} Curve
 * @property {string} name The number of the curve.
 * @property {BN} p The order of the subgroup G with a generator P, where P is a point specified by the curve.
 * @property {BN} h The cofactor of the subgroup G.
 * @property {string} M SEC1-compressed coordinate of M.
 * @property {string} N SEC1-compressed coordinate of N.
 */
const curveNistP256 = {
  name: 'p256',
  // It is defined in [draft-bar-cfrg-spake2plus-03] that
  M: '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f',
  N: '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49',
  p: new BN('115792089210356248762697446949407573529996955224135760342422259061068512044369', 10),
  h: new BN(1)
}

/**
 * Enumerate the curves.
 *
 * @readonly
 * @enum {Curve}
 */
const CURVES = {
  ed25519: curveEd25519,
  p256: curveNistP256
}

class Elliptic {
  constructor (curve) {
    const ec = new EC(curve.name)
    this.name = curve.name
    this.ec = ec.curve
    this.M = this.decodePoint(curve.M)
    this.N = this.decodePoint(curve.N)
    this.P = this.ec.g
    this.p = curve.p
    this.h = curve.h
  }

  /**
   * ...
   *
   * @param {Buffer} buf ...
   * @returns {*} ...
   */
  decodePoint (buf) {
    if (this.name === 'ed25519') {
      const b = new BN(buf.toString('hex'), 16, 'le')
      // b = [x % 2 (1bit)][y (255bits)]
      return this.ec.pointFromY(b.mod(TWO_POW_255).toString(16), b.gte(TWO_POW_255))
    }
    return this.ec.decodePoint(buf, 'hex')
  }

  /**
   * ...
   *
   * @param {*} p ...
   * @returns {Buffer} ...
   */
  encodePoint (p) {
    if (this.name === 'ed25519') {
      const x = p.getX()
      const y = p.getY()
      return Buffer.from(x.mod(new BN(2)).mul(TWO_POW_255).add(y).toArrayLike(Buffer, 'le', 32))
    }
    return Buffer.from(p.encodeCompressed())
  }
}

module.exports = {
  CURVES,
  Elliptic
}
