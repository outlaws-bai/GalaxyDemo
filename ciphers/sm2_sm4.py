import json
import base64
import typing as t
from gmssl import sm2, sm4
from Crypto.Util.Padding import pad, unpad
from . import ICipher, Constants, reandom_str, parse_sm2_pri, parse_sm2_pub


class Sm2Sm4(ICipher):
    def decrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        cipher_sm2 = sm2.CryptSM2(
            parse_sm2_pri(Constants.SM2_PRI_BASE64_KEY1),
            parse_sm2_pub(Constants.SM2_PUB_BASE64_KEY1),
        )

        encrypted_key_bytes = base64.b64decode(data["key"])
        decrypted_key = cipher_sm2.decrypt(encrypted_key_bytes[1:])
        assert decrypted_key

        encrypted_data_bytes = base64.b64decode(data["data"])
        cipher = sm4.CryptSM4()
        cipher.set_key(decrypted_key, 1)
        decrypted_padded_data = cipher.crypt_ecb(encrypted_data_bytes)
        # decrypted_data = unpad(decrypted_padded_data, 16)
        # print(decrypted_data)
        return json.loads(decrypted_padded_data.decode())

    def encrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        cipher_sm2 = sm2.CryptSM2(
            parse_sm2_pri(Constants.SM2_PRI_BASE64_KEY2),
            parse_sm2_pub(Constants.SM2_PUB_BASE64_KEY2),
        )

        random_key = reandom_str(16)

        json_data = json.dumps(data).encode()
        cipher = sm4.CryptSM4()
        cipher.set_key(random_key.encode(), 0)
        encrypted_data = cipher.crypt_ecb(json_data)

        encrypted_key = cipher_sm2.encrypt(random_key.encode())
        assert encrypted_key

        return {
            "data": base64.b64encode(encrypted_data).decode(),
            "key": base64.b64encode(b'\x04'+encrypted_key).decode(),
        }
