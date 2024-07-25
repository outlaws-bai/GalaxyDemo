import json
import base64
import typing as t
from gmssl import sm4
from . import ICipher, Constants


class Sm4Cbc(ICipher):
    def decrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        encrypted_data_bytes = base64.b64decode(data["data"])
        cipher = sm4.CryptSM4()
        cipher.set_key(Constants.SM4_KEY.encode(), 1)
        decrypted_padded_data = cipher.crypt_cbc(
            Constants.SM4_IV.encode(), encrypted_data_bytes
        )
        return json.loads(decrypted_padded_data.decode())

    def encrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        json_data = json.dumps(data).encode()
        cipher = sm4.CryptSM4()
        cipher.set_key(Constants.SM4_KEY.encode(), 0)
        encrypted_data = cipher.crypt_cbc(Constants.SM4_IV.encode(), json_data)
        return {
            "data": base64.b64encode(encrypted_data).decode(),
        }
