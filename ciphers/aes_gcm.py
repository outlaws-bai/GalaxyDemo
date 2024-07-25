import json
import base64
import typing as t
from Crypto.Cipher import AES
from . import ICipher, Constants


class AesGcm(ICipher):
    def decrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        encrypted_data_bytes = base64.b64decode(data["data"])
        cipher = AES.new(
            Constants.AES_KEY.encode(),
            AES.MODE_GCM,
            Constants.AES_IV.encode(),
            mac_len=16,
        )
        decrypted_data = cipher.decrypt_and_verify(
            encrypted_data_bytes[:-16], encrypted_data_bytes[-16:]
        )
        return json.loads(decrypted_data.decode())

    def encrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        json_data = json.dumps(data)
        cipher = AES.new(
            Constants.AES_KEY.encode(),
            AES.MODE_GCM,
            Constants.AES_IV.encode(),
            mac_len=16,
        )
        encrypted_data, tag = cipher.encrypt_and_digest(json_data.encode())
        return {"data": base64.b64encode(encrypted_data + tag).decode()}
