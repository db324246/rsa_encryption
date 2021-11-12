import Cookies from 'js-cookie'
import { Base64 } from 'js-base64'

const config = {
  expires: 7
}

// 存储 Secret
export function setSecret(secret) {
  Cookies.set('encrytion-secret', Base64.encode(secret), config)
}

// 获取 Secret
export function getSecret() {
  const value = Cookies.get('encrytion-secret')
  return value ? Base64.decode(value) : value
}

// 存储 Code
export function setCode(code) {
  Cookies.set('encrytion-code', Base64.encode(code), config)
}

// 获取 Code
export function getCode() {
  const value = Cookies.get('encrytion-code')
  return value ? Base64.decode(value) : value
}

// 获取 Code 和 Secret
export function getSecretAndCode() {
  const code = getCode()
  const secret = getSecret()

  return {
    hasCookie: code && secret,
    code,
    secret
  }
}
