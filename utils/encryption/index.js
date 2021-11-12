import NODERSA from 'node-rsa'
// import './dependencies/jsencrypt.min.js'
import JSEncrypt from './dependencies/jsencrypt.min.js'
import crypto from './dependencies/crypto-js.js'

// const crypto = window.CryptoJS || window.crypto

function spliceKeyString(str) {
  const strArr = str.split('\n')
  const res = strArr.splice(1, strArr.length - 2)
    .join('\n')
  return res
}

// 生成密钥对
export function generateRsaKeys() {
  return new Promise((r, j) => {
    try {
      const key = new NODERSA({ b: 1024 }) // 生成1024位的密钥
      key.setOptions({ encryptionScheme: 'pkcs1' })
      const publicDer = key.exportKey('pkcs8-public') // 公钥
      const privateDer = key.exportKey('pkcs8-private') // 私钥

      r({
        PRIVATE_KEY: spliceKeyString(privateDer),
        PUBLIC_KEY: spliceKeyString(publicDer)
      })
    } catch (error) {
      j('密钥对生成失败' + error)
    }
  })
}

// RsaEncryptor 加/解密 构造类
export class RsaEncryptor {
  constructor(opt) {
    const { PUBLIC_KEY, PRIVATE_KEY } = opt

    this.JSEncrypt = new JSEncrypt()
    this.JSDecrypt = new JSEncrypt()
    this.JSDecrypt.setPrivateKey(PRIVATE_KEY)
    this.JSEncrypt.setPublicKey(PUBLIC_KEY)

    this.PRIVATE_KEY = PRIVATE_KEY
    this.PUBLIC_KEY = PUBLIC_KEY
  }

  // 加密
  encrypt(msg) {
    if (!this.PUBLIC_KEY) throw Error('RsaEncryptor Error: missing PUBLIC_KEY')

    return this.JSEncrypt.encrypt(msg)
  }

  // 解密
  decrypt(data) {
    if (!this.PRIVATE_KEY) throw Error('RsaEncryptor Error: missing PRIVATE_KEY')

    return this.JSDecrypt.decrypt(data)
  }
}

// AesEncryptor 加/解密 构造类
export class AesEncryptor {
  constructor(key) {
    if (!key) throw Error('AesEncryptor Error: missing key')
    this.key = crypto.enc.Hex.parse(key)
  }

  // 加密
  encrypt(msg) {
    const srcs = crypto.enc.Utf8.parse(msg)
    const encrypted = crypto.AES.encrypt(srcs, this.key, {
      mode: crypto.mode.ECB,
      padding: crypto.pad.Pkcs7
    });
    return encrypted.toString()
  }

  // 解密
  decrypt(data) {
    const decrypt = crypto.AES.decrypt(data, this.key, {
      mode: crypto.mode.ECB,
      padding: crypto.pad.Pkcs7
    })

    return crypto.enc.Utf8.stringify(decrypt).toString()
  }
}
