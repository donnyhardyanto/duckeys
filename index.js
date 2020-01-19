'use strict'
const shortid = require('shortid')
const Blowfish = require('egoroof-blowfish')
const {isBrowser} = require('browser-or-node')
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
        if (x > 0) data = data + "\x01" + "-".repeat(8 - x)
        let salt = shortid.generate()
        let saltLength = salt.length
        let rawData = saltLength.toString() + "\x01" + salt + "\x01" + dataHash + "\x01" + dataLength.toString() + "\x01" + data
        let iv = new Uint8Array(8)
        const bf = new Blowfish(key, Blowfish.MODE.CBC, Blowfish.PADDING.SPACE)
        bf.setIv(iv)
        const encryptedData = bf.encode(rawData)
        let combinedEncryptedData = new Uint8Array(8 + encryptedData.length)
        combinedEncryptedData.set(iv, 0)
        combinedEncryptedData.set(encryptedData, 8)
        return combinedEncryptedData
    },
    shim_atob: function (s) {
        try {
            return atob(s)
        } catch (err) {
            return require('atob').atob(s)
        }
    },
    decrypt: function (key, encryptedData) {
        let iv = encryptedData.subarray(0, 8)
        let baseEncyptedData = encryptedData.subarray(8)
        const bf = new Blowfish(key, Blowfish.MODE.CBC, Blowfish.PADDING.SPACE)
        bf.setIv(iv)
        let decryptedData = bf.decode(baseEncyptedData, Blowfish.TYPE.STRING)
        let decryptedDataArray = decryptedData.split("\x01")
        let datahash = decryptedDataArray[2]
        let dataLength = parseInt(decryptedDataArray[3])
        let data = decryptedDataArray[4]
        data.slice(0, dataLength - 1)
        let calculatedDataHash = this.hash(data)
        if (calculatedDataHash!=datahash) {
          throw new Error('KeyManager: Hash not consistent')
        }
        return data
    }
}

const duckeys = {
    Duckeys
}
module.exports = duckeys
