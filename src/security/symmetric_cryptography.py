import base64
from os import urandom
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Pyro4.util import json

from src.manage_logs_v_2 import ManagementLogs, ComponentType, LogType


def generate_symmetric_key():
    return Fernet.generate_key()


def encrypt_data(key, data, management_logs: ManagementLogs):
    management_logs.log_message(ComponentType.SYMETRIC_CRYPTOGRAPHY, 'SymetricCryptography -> Encrypting data', LogType.ENCRYPTION, True)
    data_bytes = json.dumps(data).encode("utf-8")
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    management_logs.log_message(ComponentType.SYMETRIC_CRYPTOGRAPHY, 'SymmetricCryptography -> Encrypting data', LogType.ENCRYPTION, True)
    encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()
    iv_base64 = base64.b64encode(iv).decode()
    encrypted_data_base64 = base64.b64encode(encrypted_data).decode()
    management_logs.log_message(ComponentType.SYMETRIC_CRYPTOGRAPHY, 'SymmetricCryptography -> Data encrypted', LogType.ENCRYPTION, True)
    return iv_base64, encrypted_data_base64


def decrypt_data_symetric_key(key, iv_base64, encrypted_data_base64, management_logs: ManagementLogs):
    management_logs.log_message(ComponentType.SYMETRIC_CRYPTOGRAPHY, 'SymmetricCryptography -> Decrypting data', LogType.DECRYPTION, True)
    iv = base64.b64decode(iv_base64)
    encrypted_data = base64.b64decode(encrypted_data_base64)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    management_logs.log_message(ComponentType.SYMETRIC_CRYPTOGRAPHY, 'SymmetricCryptography -> Data decrypted', LogType.DECRYPTION, True)
    return json.loads(decrypted_data.decode("utf-8"))
