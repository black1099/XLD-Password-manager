import base64

from enum import Enum, auto

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class EncryptedData:
    class Status(Enum):
        ENCODED = auto()
        DECODED = auto()

    def __init__(self, key, ciphertext, nonce, tag):
        self.key = key
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
        self.status = self.Status.DECODED

    @staticmethod
    def from_encoded_data(key, ciphertext, nonce, tag):
        encrypted_data = EncryptedData(key, ciphertext, nonce, tag)
        encrypted_data.status = encrypted_data.Status.ENCODED
        return encrypted_data

    def __repr__(self):
        self.__encoded_data()
        return f"key: {self.key}\nciphertext: {self.ciphertext}\nnonce: {self.nonce}\ntag: {self.tag}"

    def to_dict(self):
        if self.status == self.Status.ENCODED:
            self.__decoded_data()

        return {
            'key': self.key,
            'ciphertext': self.ciphertext,
            'nonce': self.nonce,
            'tag': self.tag
        }

    def get(self):
        if self.status == self.Status.DECODED:
            self.__encoded_data()

        return {
            'key': self.key,
            'ciphertext': self.ciphertext,
            'nonce': self.nonce,
            'tag': self.tag
        }

    def __encoded_data(self):
        if self.status == self.Status.ENCODED:
            return

        self.key = base64.b64encode(self.key).decode('utf-8')
        self.ciphertext = base64.b64encode(self.ciphertext).decode('utf-8')
        self.nonce = base64.b64encode(self.nonce).decode('utf-8')
        self.tag = base64.b64encode(self.tag).decode('utf-8')

        self.status = self.Status.ENCODED

    def __decoded_data(self):
        if self.status == self.Status.DECODED:
            return

        self.key = base64.b64decode(self.key.encode('utf-8'))
        self.ciphertext = base64.b64decode(self.ciphertext.encode('utf-8'))
        self.nonce = base64.b64decode(self.nonce.encode('utf-8'))
        self.tag = base64.b64decode(self.tag.encode('utf-8'))

        self.status = self.Status.DECODED


class CryptoManager:

    def __init__(self):
        pass

    def encrypt(self, data, key=None):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not key:
            key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        return EncryptedData(key, ciphertext, nonce, tag)

    def decrypt(self, encrypted_data):
        data = encrypted_data.to_dict()
        key = data.get("key")
        cipher = AES.new(key, AES.MODE_EAX, nonce=data.get("nonce"))
        try:
            plaintext = cipher.decrypt_and_verify(data.get("ciphertext"), data.get("tag"))
            return plaintext
        except ValueError as e:
            raise ValueError("Decryption failed or data has been tampered with.") from e