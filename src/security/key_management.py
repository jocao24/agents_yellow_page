import base64
import json
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from src.manage_data import log_message
from src.security.symmetric_cryptography import generate_symmetric_key


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def generate_public_key(private_key: rsa.RSAPrivateKey):
    return private_key.public_key()


def generate_keys_asimetrics():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    return private_key, public_key


def load_public_key(public_key: str):
    public_key_bytes = str(public_key).encode()
    return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())


def serialize_and_encode_private_key(private_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(pem_private_key).decode('utf-8')


def load_private_key_from_base64(base64_private_key):
    private_key_bytes = base64.b64decode(base64_private_key)
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,  # Aquí podrías especificar una contraseña si la clave privada está cifrada
        backend=default_backend()
    )
    return private_key

def load_public_key_from_base64(base64_public_key):
    public_key_bytes = base64.b64decode(base64_public_key)
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return public_key


def serialize_and_encode_public_key(public_key):
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(pem_public_key).decode('utf-8')


def load_private_key(private_key: str):
    private_key_bytes = str(private_key).encode()
    return serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def encrypt_data_with_public_key(public_key: rsa.RSAPublicKey, data: dict, id_agent):
    try:
        # Convertir los datos a bytes
        data_bytes = json.dumps(data).encode("utf-8")

        # Generar un IV aleatorio
        iv = urandom(16)

        shared_key = generate_symmetric_key()

        # Decodificar la clave de base64 a bytes
        shared_key_bytes = base64.urlsafe_b64decode(shared_key)

        # Crear el objeto de cifrado AES usando la clave simétrica
        cipher = Cipher(algorithms.AES(shared_key_bytes), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        # Cifrar los datos
        encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()

        # Cifrar la clave simétrica con la clave pública RSA
        encrypted_key = public_key.encrypt(
            shared_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Codificar el IV, los datos cifrados y la clave cifrada en base64 para su transmisión o almacenamiento
        iv_base64 = base64.b64encode(iv).decode()
        encrypted_data_base64 = base64.b64encode(encrypted_data).decode()
        encrypted_key_base64 = base64.b64encode(encrypted_key).decode()

        return {
            "iv": iv_base64,
            "data": encrypted_data_base64,
            "key": encrypted_key_base64,
            "id": id_agent
        }
    except Exception as e:
        log_message(f"Error encrypting data with public key for agent {id_agent}: {e}")
        return None


def decrypt_data_with_private_key(encrypted_key, iv, encrypted_data, private_key: rsa.RSAPrivateKey):
    # Decode the base64 encoded encrypted AES key, IV, and data
    encrypted_key = base64.b64decode(encrypted_key)
    iv = base64.b64decode(iv)
    encrypted_data = base64.b64decode(encrypted_data)

    # Decrypt the AES key using the RSA private key
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the data using the decrypted AES key and IV
    cipher = Cipher(algorithms.AES(decrypted_key[:32]), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data
