import json
import base64
import typing as t
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from . import ICipher, Constants


class AesEcb(ICipher):
    cipher = AES.new(Constants.AES_KEY.encode(), AES.MODE_ECB)

    def decrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        encrypted_data_bytes = base64.b64decode(data["data"])
        decrypted_data = unpad(
            self.cipher.decrypt(encrypted_data_bytes), AES.block_size
        )
        return json.loads(decrypted_data.decode())

    def encrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        json_data = json.dumps(data)
        encrypted_data = self.cipher.encrypt(pad(json_data.encode(), AES.block_size))
        return {"data": base64.b64encode(encrypted_data).decode()}
