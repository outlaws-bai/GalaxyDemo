import json
import base64
import typing as t
from gmssl import sm2
from . import ICipher, Constants, parse_sm2_pri, parse_sm2_pub


class Sm2(ICipher):
    def decrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        cipher = sm2.CryptSM2(
            parse_sm2_pri(Constants.SM2_PRI_BASE64_KEY1),
            parse_sm2_pub(Constants.SM2_PUB_BASE64_KEY1),
            asn1=False,
        )
        encrypted_data_bytes = base64.b64decode(data["data"])
        decrypted_data = cipher.decrypt(encrypted_data_bytes[1:])
        assert decrypted_data
        return json.loads(decrypted_data.decode())

    def encrypt(self, data: dict[str, t.Any]) -> dict[str, t.Any]:
        cipher = sm2.CryptSM2(
            parse_sm2_pri(Constants.SM2_PRI_BASE64_KEY2),
            parse_sm2_pub(Constants.SM2_PUB_BASE64_KEY2),
            asn1=False,
        )
        json_data = json.dumps(data).encode()
        encrypted_data = cipher.encrypt(json_data)
        assert encrypted_data
        return {
            "data": base64.b64encode(b"\x04" + encrypted_data).decode(),
        }
