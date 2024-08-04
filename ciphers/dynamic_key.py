import json
import base64
from . import ICipher, Constants
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad, unpad


class DynamicKey(ICipher):
    key: bytes

    def decrypt(self, data):
        encrypted_key_bytes = base64.b64decode(data["key"])
        rsa_key = RSA.import_key(base64.b64decode(Constants.RSA_PRI_BASE64_KEY1))
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        decrypted_key = cipher_rsa.decrypt(encrypted_key_bytes, 0)
        assert isinstance(decrypted_key, bytes)
        print("decrypted_key: ", decrypted_key)
        self.key = decrypted_key
        cipher_aes = AES.new(decrypted_key, AES.MODE_ECB)
        encrypted_data_bytes = base64.b64decode(data["data"])
        decrypted_data = unpad(cipher_aes.decrypt(encrypted_data_bytes), AES.block_size)
        return json.loads(decrypted_data.decode())

    def encrypt(self, data):
        json_data = json.dumps(data)
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(json_data.encode(), AES.block_size))
        return {"data": base64.b64encode(encrypted_data).decode()}
