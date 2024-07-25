import json
import base64
import typing as t
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from . import ICipher, Constants


class DesCbc(ICipher):
    def decrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        encrypted_data_bytes = base64.b64decode(data["data"])
        cipher = DES.new(
            Constants.DES_KEY.encode(), DES.MODE_CBC, Constants.DES_IV.encode()
        )
        decrypted_data = unpad(cipher.decrypt(encrypted_data_bytes), DES.block_size)
        return json.loads(decrypted_data.decode())

    def encrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        json_data = json.dumps(data)
        cipher = DES.new(
            Constants.DES_KEY.encode(), DES.MODE_CBC, Constants.DES_IV.encode()
        )
        encrypted_data = cipher.encrypt(pad(json_data.encode(), DES.block_size))
        return {"data": base64.b64encode(encrypted_data).decode()}
