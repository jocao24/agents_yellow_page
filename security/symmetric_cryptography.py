import base64
from os import urandom
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from Pyro4.util import json


def generate_symmetric_key():
    # Esta función generará una clave simétrica segura
    return Fernet.generate_key()


def encrypt_data(key, data):
    """
    Cifra los datos utilizando una clave simétrica.

    Args:
        key (bytes): La clave simétrica para cifrar los datos.
        data (dict): Los datos (un diccionario) que se van a cifrar.

    Returns:
        tuple: El vector de inicialización (iv) y los datos cifrados, ambos en base64.
    """
    # Convertir los datos a bytes
    data_bytes = json.dumps(data).encode("utf-8")

    # Generar un IV aleatorio
    iv = urandom(16)

    # Crear el objeto de cifrado
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Cifrar los datos
    encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()

    # Codificar el IV y los datos cifrados en base64 para su transmisión o almacenamiento
    iv_base64 = base64.b64encode(iv).decode()
    encrypted_data_base64 = base64.b64encode(encrypted_data).decode()

    return iv_base64, encrypted_data_base64


def decrypt_data_symetric_key(key, iv_base64, encrypted_data_base64):
    """
    Descifra los datos utilizando una clave simétrica.

    Args:
        key (bytes): La clave simétrica para descifrar los datos.
        iv_base64 (str): El vector de inicialización en base64.
        encrypted_data_base64 (str): Los datos cifrados en base64.

    Returns:
        dict: Los datos descifrados.
    """
    # Decodificar el IV y los datos cifrados de base64 a bytes
    iv = base64.b64decode(iv_base64)
    encrypted_data = base64.b64decode(encrypted_data_base64)

    # Crear el objeto de descifrado
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descifrar los datos
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return json.loads(decrypted_data.decode("utf-8"))