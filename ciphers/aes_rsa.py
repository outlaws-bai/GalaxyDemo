import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad, unpad
from . import ICipher, Constants, reandom_str


class AesRsa(ICipher):
    def decrypt(self, data):
        encrypted_key_bytes = base64.b64decode(data["key"])
        rsa_key = RSA.import_key(base64.b64decode(Constants.RSA_PRI_BASE64_KEY1))
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        decrypted_key = cipher_rsa.decrypt(encrypted_key_bytes, 0)
        assert isinstance(decrypted_key, bytes)

        cipher_aes = AES.new(decrypted_key, AES.MODE_ECB)
        encrypted_data_bytes = base64.b64decode(data["data"])
        decrypted_data = unpad(cipher_aes.decrypt(encrypted_data_bytes), AES.block_size)
        return json.loads(decrypted_data.decode())

    def encrypt(self, data):
        random_key = reandom_str(32)

        cipher_aes = AES.new(random_key.encode(), AES.MODE_ECB)
        json_data = json.dumps(data)
        encrypted_data = cipher_aes.encrypt(pad(json_data.encode(), AES.block_size))

        rsa_key = RSA.import_key(base64.b64decode(Constants.RSA_PUB_BASE64_KEY2))
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        encrypted_key = cipher_rsa.encrypt(random_key.encode())

        return {
            "data": base64.b64encode(encrypted_data).decode(),
            "key": base64.b64encode(encrypted_key).decode(),
        }
