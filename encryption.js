import { getSeverPublicKey, getClientSecret } from '@/api/app/encrypt'
import { generateRsaKeys, RsaEncryptor, AesEncryptor } from '@/utils/encryption'
import { setSecret, getSecretAndCode, setCode } from '@/utils/cookies/encryption'

/**
 * 截取客户端公钥首尾字母，并用服务端公钥加密
 * @param {string 客户端公钥} publicKey
 * @returns Object<clientPubKey, enClientPubKey>
 */
function splitClientPublicKey(publicKey, serverRsaEncryptor) {
  const keysArr = publicKey.split('')
  const clientPubKey = keysArr.splice(1, keysArr.length - 2)
    .join('')
  return {
    clientPubKey,
    enClientPubKey: serverRsaEncryptor.encrypt(keysArr.join(''))
  }
}

export default {
  namespaced: true,
  state: {
    encryptionStatus: true, // 加密模块初始化
    serverPublicKey: '', // 服务端公钥
    clientPublicKey: '', // 客户端公钥
    clientPrivateKey: '', // 客户端私钥
    serverRsaEncryptor: null,
    clientRsaEncryptor: null,
    secretAesEncryptor: null,
    appSecret: '',
    appCode: ''
  },
  mutations: {
    SET_SERVER_PUBLICKEY(state, publicKey) {
      state.serverPublicKey = publicKey
    },
    SET_CLIENT_PUBLICKEY(state, publicKey) {
      state.clientPublicKey = publicKey
    },
    SET_CLIENT_PRIVATEKEY(state, privateKey) {
      state.clientPrivateKey = privateKey
    },
    // 初始化客户端加密类
    INIT_SECRET_AES_ENCRYPTOR(state) {
      state.secretAesEncryptor = new AesEncryptor('1234123412ABCDEF')
    },
    // 初始化客户端加密类
    INIT_CLIENT_RSA_ENCRYPTOR(state) {
      state.clientRsaEncryptor = new RsaEncryptor({
        PUBLIC_KEY: state.clientPublicKey,
        PRIVATE_KEY: state.clientPrivateKey
      })
    },
    // 初始化服务端加密类
    INIT_SERVER_RSA_ENCRYPTOR(state) {
      state.serverRsaEncryptor = new RsaEncryptor({
        PUBLIC_KEY: state.serverPublicKey
      })
    },
    SET_APP_SECRET(state, secret) {
      state.appSecret = secret
    },
    SET_APP_CODE(state, code) {
      state.appCode = code
    },
    SET_ENCRYPTION_STATUS(state, flag) {
      state.encryptionStatus = flag
    }
  },
  actions: {
    async ENCRYPTION_INIT({ dispatch, commit, state }, flag) {
      !state.secretAesEncryptor && commit('INIT_SECRET_AES_ENCRYPTOR')
      const { hasCookie, code, secret } = getSecretAndCode()

      if (hasCookie && !flag) { // cookie 存在的情况下直接存储参数
        if (secret === state.secretAesEncryptor.encrypt(state.appSecret)) return
        commit('SET_APP_SECRET', state.secretAesEncryptor.decrypt(secret))
        commit('SET_APP_CODE', state.secretAesEncryptor.decrypt(code))
        return
      }
      try {
        await dispatch('GET_SERVER_PUBLICKEY')
        // 生成客户端密钥
        const { PRIVATE_KEY, PUBLIC_KEY } = await generateRsaKeys()
        commit('SET_CLIENT_PUBLICKEY', PUBLIC_KEY)
        commit('SET_CLIENT_PRIVATEKEY', PRIVATE_KEY)
        commit('INIT_CLIENT_RSA_ENCRYPTOR')

        // 获取客户端 Secret 和 Code
        await dispatch('GET_ClIENT_SECRET')
      } catch (error) {
        commit('SET_ENCRYPTION_STATUS', false)
        console.log(error)
      }
    },
    // 获取服务端公钥
    async GET_SERVER_PUBLICKEY({ commit, dispatch }) {
      try {
        const { data: publicKey } = await getSeverPublicKey()
        commit('SET_SERVER_PUBLICKEY', publicKey)
      } catch (error) {
        throw Error('system error: 获取服务端公钥失败')
      }
    },
    // 获取客户端加密的应用code和secret
    async GET_ClIENT_SECRET({ state, commit, dispatch }) {
      try {
        !state.serverRsaEncryptor && commit('INIT_SERVER_RSA_ENCRYPTOR')
        const {
          serverPublicKey,
          clientPublicKey,
          serverRsaEncryptor,
          clientRsaEncryptor
        } = state

        const { data } = await getClientSecret({
          servicePubKey: serverPublicKey,
          ...splitClientPublicKey(clientPublicKey, serverRsaEncryptor)
        })

        const { s, c } = JSON.parse(clientRsaEncryptor.decrypt(data))

        setCode(state.secretAesEncryptor.encrypt(c))
        setSecret(state.secretAesEncryptor.encrypt(s))

        commit('SET_APP_SECRET', s)
        commit('SET_APP_CODE', c)
        commit('SET_ENCRYPTION_STATUS', true)
      } catch (error) {
        console.log(error)
        throw Error('system error: 获取服务端公钥失败', error)
      }
    }
  }
}
