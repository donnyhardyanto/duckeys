'use strict'
const shortid = require('shortid')
const Blowfish = require('egoroof-blowfish')
const { isBrowser } = require('browser-or-node')
let crypto = null
if (isBrowser) {
  crypto = require('crypto-browserify')
} else {
  crypto = require('crypto')
}

const Duckeys = {
  generateSalt: function () {
    return shortid.generate() + shortid.generate()
  },
  hash: function (d) {
    const sha256 = crypto.createHash('sha256')
    sha256.update(d)
    return sha256.digest('base64')
  },
  deriveFrom: function (a, b) {
    let self = this
    return {
      a: self.hash(a + b),
      b: self.hash(b + a)
    }
  },
  encrypt: function (key, data) {
    let dataHash = this.hash(data)
    let dataLength = data.length
    let x = dataLength % 8
    if (x > 0) data = data + ' '.repeat(x)
    let salt = shortid.generate()
    let saltLength = salt.length
    let rawData = saltLength.toString() + ' ' + salt + ' ' + dataHash + ' ' + dataLength.toString() + ' ' + data
    const bf = new Blowfish(key, Blowfish.MODE.CBC, Blowfish.PADDING.NULL)
    bf.setIv('12345678')
    const encryptedData = bf.encode(rawData)
    return btoa(String.fromCharCode.apply(null, encryptedData))
  },
  shim_atob: function (s) {
    try {
      return atob(s)
    } catch (err) {
      return require('atob')
    }
  }
share
decrypt: function (key, encryptedData) {
  let uint8ArrayDecoded = new Uint8Array(atob(encryptedData).split('').map(function (c) {
    return c.charCodeAt(0)
  }))
  const bf = new Blowfish(key, Blowfish.MODE.CBC, Blowfish.PADDING.NULL)
  bf.setIv('12345678')
  const decryptedData = bf.decode(uint8ArrayDecoded, Blowfish.TYPE.STRING)
  let decryptedDataArray = decryptedData.split(' ', 4)
  let dataLength = parseInt(decryptedDataArray[3])
  let data = decryptedDataArray[4]
  data.slice(0, dataLength - 1)
  return data
}
}

const duckeys = {
  Duckeys
}
module.exports = duckeys
