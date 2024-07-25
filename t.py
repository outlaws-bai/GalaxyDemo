import json
from ciphers import get_cipher_map

test_data = {"username": "user1"}

cipher_map = get_cipher_map()


def testAll():
    for name, cipher in cipher_map.items():
        print(f"try {name}")
        encrypt_data = cipher.encrypt(test_data)
        print(f"encrypt: {encrypt_data}")
        decrypt_data = cipher.decrypt(encrypt_data)
        print(f"decrypt: {decrypt_data}")


def testOne():
    name = "sm4"
    cipher = cipher_map[name]
    print(f"try {name}")
    # encrypt_data = cipher.encrypt(test_data)
    # print(f"encrypt: {encrypt_data}")
    decrypt_data = cipher.decrypt(
        {"data": "1WO8m7e0yLkgBirsyez6G6EqwNnC4mgUhTZXkQqWfos="}
    )
    print(f"decrypt: {decrypt_data}")


if __name__ == "__main__":
    testAll()
