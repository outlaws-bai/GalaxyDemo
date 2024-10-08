import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from . import ICipher, Constants


class AesCbc(ICipher):
    def decrypt(self, data):
        encrypted_data_bytes = base64.b64decode(data["data"])
        cipher = AES.new(
            Constants.AES_KEY.encode(), AES.MODE_CBC, Constants.AES_IV.encode()
        )
        decrypted_data = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)
        return json.loads(decrypted_data.decode())

    def encrypt(self, data):
        json_data = json.dumps(data)
        cipher = AES.new(
            Constants.AES_KEY.encode(), AES.MODE_CBC, Constants.AES_IV.encode()
        )
        encrypted_data = cipher.encrypt(pad(json_data.encode(), AES.block_size))
        return {"data": base64.b64encode(encrypted_data).decode()}
