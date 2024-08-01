import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from . import ICipher, Constants


class Rsa(ICipher):
    def decrypt(self, data):
        encrypted_data_bytes = base64.b64decode(data["data"])
        rsa_key = RSA.import_key(base64.b64decode(Constants.RSA_PRI_BASE64_KEY1))
        cipher = PKCS1_v1_5.new(rsa_key)
        decrypted_data = cipher.decrypt(encrypted_data_bytes, 0)
        assert isinstance(decrypted_data, bytes)
        return json.loads(decrypted_data.decode())

    def encrypt(self, data):
        json_data = json.dumps(data).encode()
        rsa_key = RSA.import_key(base64.b64decode(Constants.RSA_PUB_BASE64_KEY2))
        cipher = PKCS1_v1_5.new(rsa_key)
        encrypted_data = cipher.encrypt(json_data)
        return {"data": base64.b64encode(encrypted_data).decode()}
