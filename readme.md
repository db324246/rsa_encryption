
### encryption 加密模块

在正式环境中，我们会默认开启应用加密的环境变量 `VUE_APP_REQUEST_ENCRYPT`。<br>
开启后打开网页就会触发我们的 `encryption` 加密模块

### encryption 初始化流程
<div class='card'>

1. 浏览网页触发 `vuex action` 方法 `ENCRYPTION_INIT` 进行加密初始化；
2. `ENCRYPTION_INIT` 方法中首先会从本地的 `Cookie` 中获取加密信息，看近期是否进行过加密初始化工作；
3. 加密方式我们采用的是: `AES` 与 `RSA` 两个算法进行加密。第一步就是通过接口先获取服务端的 `RSA公钥`；
4. 通过 `node-rsa` 插件来生成客户端的 `RSA密钥对`；
5. 通过获取到的 `服务端RSA公钥` 来加密我们生成 `客户端RSA公钥`，并发送请求传递给后端；
6. 后端通过自己的 `服务端RSA私钥` 解密后就获取到我们的 `客户端RSA公钥` 了；
7. 后端会通过我们的 `客户端RSA公钥` 来加密一段密文并在上一次的接口中返回给我们；
8. 我们使用 `服务端RSA私钥` 解密并获取到真实的密文信息；
9. 将密文直接存储到 vuex 仓库中以便后续发送请求时携带密文信息，同时再使用 `AES算法` 将密文加密后存储到 `Cookie` 中防止后续重复进行加密初始化工作；
</div>

### RSA 非对称加密原理
<div class='card'>

从上面的流程中，已经能看出 RSA 非对称加密的原理了。
+ 前后端分别生成了一对 `RSA公钥、私钥`，并通过接口交换自己的 `公钥`。
+ 在后续的请求交互中，分别使用对方的 `公钥` 进行加密发送信息和自己的 `私钥` 进行解密获取信息
</div>

### 代码目录

+ `./src/storeGlobalModule/encryption.js` 加密仓库模块
+ `./src/utils/encryption/index.js` 加密类的封装