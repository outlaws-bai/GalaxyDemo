import base64
import random
import string
from abc import ABCMeta, abstractmethod


class ICipher(metaclass=ABCMeta):
    @abstractmethod
    def decrypt(self, data):
        """解密"""

    @abstractmethod
    def encrypt(self, data):
        """加密"""


def parse_sm2_pri(pri):
    pri_hex = base64.b64decode(pri).hex()
    return pri_hex[72 : 72 + 64]


def parse_sm2_pub(pub):
    pub_hex = base64.b64decode(pub).hex()
    return pub_hex[-128:]


def reandom_str(length):
    return "".join(
        [random.choice(string.ascii_letters + string.digits) for _ in range(length)]
    )


def get_cipher_map():
    from .aes_cbc import AesCbc
    from .aes_ecb import AesEcb
    from .aes_gcm import AesGcm
    from .aes_rsa import AesRsa
    from .rsa import Rsa
    from .sm2_sm4 import Sm2Sm4
    from .sm2 import Sm2
    from .sm4_cbc import Sm4Cbc
    from .des import DesCbc
    from .des3 import DesCbc3
    from .dynamic_key import DynamicKey

    return {
        "aes-cbc": AesCbc(),
        "aes-ecb": AesEcb(),
        "aes-gcm": AesGcm(),
        "rsa": Rsa(),
        "aes-rsa": AesRsa(),
        "sm2": Sm2(),
        "sm4-cbc": Sm4Cbc(),
        "sm2-sm4": Sm2Sm4(),
        "des-cbc": DesCbc(),
        "des3-cbc": DesCbc3(),
        "dynamic-key": DynamicKey(),
    }


class Constants:
    AES_KEY = "32byteslongsecretkeyforaes256!aa"
    AES_IV = "16byteslongiv456"
    AES_TAG_LEN = 128
    RSA_PUB_BASE64_KEY1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7JoQAWLsovzHjaUMZg2lwO4LCuP97mitUc4chqRlQD3NgyCWLqEnYyM+OJ7i6cyMuWLwGtMi29DoKLjpE/xRZR0OUk46PDCAtyDgIyejK7c7KlZTbiqb4PtiJNLZgg0UP62kLMycnpY/wg/R2G9g+7MiJWUV5SR+Lhryv8CWezQIDAQAB"
    RSA_PRI_BASE64_KEY1 = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALsmhABYuyi/MeNpQxmDaXA7gsK4/3uaK1RzhyGpGVAPc2DIJYuoSdjIz44nuLpzIy5YvAa0yLb0OgouOkT/FFlHQ5STjo8MIC3IOAjJ6MrtzsqVlNuKpvg+2Ik0tmCDRQ/raQszJyelj/CD9HYb2D7syIlZRXlJH4uGvK/wJZ7NAgMBAAECgYAhgbhRbZF4rp6Kdh6e00HN58G2BjQrl4MZeCOh+aoABPwlwD/EnMk36GAMtfzjWNjcI+PqGXT0GI7JotQo5ThpoweXX/uoeGOW+UkYLA6a67lmxfoZsDtY2+jnaWIs2c7Itz3ClRxo4tYwCoPNjtaBpMfPgZaYg2QN8/wLQPI66wJBAM0xpjb2OlLDs75lVxbm6v6Dx3YBS20GSqJqvf+14a/k7mrZ3PmAHOfqTqKOwbVQJmLbeOpU+sUBpeLpILKOCLcCQQDpfSsDhdosC6qTL9XnF2jS49iws2RBKw5YjDkClwA6VMNj5uzL1Rl7/AimLRMnB4BwrD95ksuOJsqNXW6wRGibAkAkk28PaQCodB38GFBX0r2ctJy/Wie5vV9caC6KAD/EfMhK357WEpIUfN2beFrrGOhewsRg8NjqeQq60dd0PIEtAkBYAm03O7n8Bj26kzpejA1gCLBCEqyEf/U9XUWT+1UDp7Wqr32sa1vaxyp/cNgaSxKX5eVbLwD5SRfqZ0B0wqRnAkATpUNiCqjQVS+OI5dwjoI1Rx3oI8pyKWOg3+QIHIRgL3pc8HLdZ2BkX4Vf6ANb4+noQnD/di1Mj+0pUL8RhIJE"
    RSA_PUB_BASE64_KEY2 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrfqYv278oDvreohZeR+UMiNSJC2FG4u8dSNC/hj88lw7eULQOiuUnsZ4eineeFOquXckjhkh1AJsd87+Nz1ZQB61dY3NmVR5Tk+2wH/kNdiVCoRrbULs29Tms17IyrZZU9WQFQbBxC/g6n5zwp6ST/siGRfHAwVVbq+iccQfdpwIDAQAB"
    RSA_PRI_BASE64_KEY2 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKt+pi/bvygO+t6iFl5H5QyI1IkLYUbi7x1I0L+GPzyXDt5QtA6K5Sexnh6Kd54U6q5dySOGSHUAmx3zv43PVlAHrV1jc2ZVHlOT7bAf+Q12JUKhGttQuzb1OazXsjKtllT1ZAVBsHEL+DqfnPCnpJP+yIZF8cDBVVur6JxxB92nAgMBAAECgYAghb2lcNKBGcooo2uDiLXe2SoZLT/O7iVzk8YGtEJUzr7imUJ0SZHoo639U7wYjhXtaFrHMmWWTr2cAggvMAVJi5fZYYJLbYdc8O5QCKi6PzV2J2NxYyuABL5yarvy4Ji0twnDjlqBYqrjOsxJbeMv58CHLKqduIZuxppGGOoRQQJBANTV3JEg6xJdPXsF9ztOf03BNkvpibuUSNbTssTdzEtLMQW7zd5y1qTCwUbf+e2UsRIYPn5DwOlTu8SaE97Zz8ECQQDORm7szA0WL1OTYob0U1NSSFDn8Jg7FyX5md6ndL3KNTKBDBfe3hNpauLi01lTMbO3MoriOWsFiN++6dZAdwdnAkEAq6PcwN1/Ncwj7Lae7yEa4SXUF9w6yx+GrlkDbmhAfOginLEcES0jlLPLEtFFySeEtUb//uu9A24XmzF2nN2jAQJABgL7fJ89ymW6s9LtR/WdugotgXT7ms1D6BBZ8ttuJJSEUkp975rdSfc5gY7TTZ9nM3GfppQx0El66994xQwzBQJAct1HPeCVROxyEHNwsiRH9wqR5P4B59Mo1714R7ozsdTpVx8FWmqi+OQIJt+IizYgRyQ09qORAFei9AHeQtxKiw=="

    SM2_PUB_BASE64_KEY1 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEBv9Z+xbmSOH3W/V9UEpU1yUiJKNGh/I8EiENTPYxX3GujsZyKhuEUzxloKCATcNaKWi7w/yK3PxGONM4xvMlIQ=="
    SM2_PRI_BASE64_KEY1 = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgWmIprZ5a6TsqRUgy32J+F22AYIKl+14P4qlw/LPPCcagCgYIKoEcz1UBgi2hRANCAAQG/1n7FuZI4fdb9X1QSlTXJSIko0aH8jwSIQ1M9jFfca6OxnIqG4RTPGWgoIBNw1opaLvD/Irc/EY40zjG8yUh"
    SM2_PUB_BASE64_KEY2 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE/1kmIjlOfsqG9hN4b/O3hiSI91ErgVDeqB9YOgCFiUiFyPo32pCHh691zGnoAj0l/P132CyLgBeH6TUa/TrLUg=="
    SM2_PRI_BASE64_KEY2 = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgP8vW9tEh0dMP5gJNsol5Gyc6jvvgK1NRqOVg8VaLYVygCgYIKoEcz1UBgi2hRANCAAT/WSYiOU5+yob2E3hv87eGJIj3USuBUN6oH1g6AIWJSIXI+jfakIeHr3XMaegCPSX8/XfYLIuAF4fpNRr9OstS"

    SM4_KEY = "16byteslongkey12"
    SM4_IV = AES_IV
    DES_KEY = "12345678"
    DES_IV = "12345678"
    DES3_KEY = "24byteslongKeyfordes3!aa"
    DES3_IV = "8bytesIv"
