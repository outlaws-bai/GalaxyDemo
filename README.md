# GalaxyDemo
HTTP报文二次加密的具体实现，用于测试 https://github.com/outlaws-bai/Galaxy 中的示例

> python 3.8+

**场景**

`AesCbc`: 通过AES CBC模式使用指定的密钥和IV对用户输入的数据进行加密请求，并对服务器响应的数据进行解密。

`AesEcb`: 通过AES ECB模式使用指定的密钥对用户输入的数据进行加密请求，并对服务器响应的数据进行解密。

`AesGcm`: 通过AES GCM模式使用指定的密钥和IV对用户输入的数据进行加密请求，并对服务器响应的数据进行解密。

`AesRsa`: 使用随机生成的AES密钥加密用户数据，通过RSA加密AES密钥后发送请求，并在收到响应后解密AES密钥和数据。

`DynamicKey`: 客户端生成随机AES密钥，AES加密数据，RSA加密随机密钥，响应用随机密钥通过AES加密。

`Rsa`: 使用RSA公钥加密用户输入的数据，并将加密后的数据发送到服务器；服务器响应的加密数据使用另外一组RSA私钥解密后展示。

`Sm2`: 使用SM2算法对用户输入的数据进行加密，并将加密后的数据发送到服务器；服务器响应的加密数据使用另外一组SM2私钥进行解密。

`Sm2Sm4`: 使用随机生成的SM4密钥加密用户数据，通过SM2加密SM4密钥后发送请求，并在收到响应后解密SM4密钥和数据。

`Sm4Cbc`: 使用SM4算法在CBC模式下对数据进行加密请求，并展示解密后的结果。

`DES`：通过DES CBC模式使用指定的密钥和IV对用户输入的数据进行加密请求，并对服务器响应的数据进行解密。

`3DES`：通过DES3 CBC模式使用指定的密钥和IV对用户输入的数据进行加密请求，并对服务器响应的数据进行解密。

`LinkPassiveScanner`: AES CBC加密 + jinja2 SSTI注入，用来测试Galaxy联动被动代理扫描器。

**安装依赖**

```bash
pip install -r requirements.txt
```

**启动**
```bash
python manager.py
```

