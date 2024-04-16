import base64
import json
from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from src.manage_logs import ManagementLogs
from src.security.symmetric_cryptography import generate_symmetric_key


def generate_private_key(management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Generating private key')
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    management_logs.log_message('Key Management -> Private key generated')
    return key


def generate_public_key(private_key: rsa.RSAPrivateKey, management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Generating public key')
    key = private_key.public_key()
    management_logs.log_message('Key Management -> Public key generated')
    return key


def generate_keys_asimetrics(management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Generating asymmetric keys')
    private_key = generate_private_key(management_logs)
    public_key = generate_public_key(private_key, management_logs)
    management_logs.log_message('Key Management -> Asymmetric keys generated')
    return private_key, public_key


def load_public_key(public_key: str, management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Loading public key')
    public_key_bytes = str(public_key).encode()
    key_ser = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    management_logs.log_message('Key Management -> Public key loaded')
    return key_ser


def serialize_and_encode_private_key(private_key, management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Serializing and encoding private key')
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    management_logs.log_message('Key Management -> Private key serialized and encoded')
    return base64.b64encode(pem_private_key).decode('utf-8')


def load_private_key_from_base64(base64_private_key):
    private_key_bytes = base64.b64decode(base64_private_key)
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
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


def serialize_and_encode_public_key(public_key, management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Serializing and encoding public key')
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    management_logs.log_message('Key Management -> Public key serialized and encoded')
    return base64.b64encode(pem_public_key).decode('utf-8')


def serialize_public_key(public_key, management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Serializing public key')
    key_ser = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    management_logs.log_message('Key Management -> Public key serialized')
    return key_ser


def encrypt_data_with_public_key(public_key: rsa.RSAPublicKey, data: dict, id_agent, management_logs: ManagementLogs):
    management_logs.log_message(f'Key Management -> Encrypting data with hybrid encryption for agent {id_agent}')
    try:
        management_logs.log_message(f'Key Management -> Data to be encrypted: {data}')
        data_bytes = json.dumps(data).encode("utf-8")
        iv = urandom(16)
        management_logs.log_message('Key Management -> Generating symmetric key')
        shared_key = generate_symmetric_key()
        management_logs.log_message('Key Management -> Symmetric key generated')

        shared_key_bytes = base64.urlsafe_b64decode(shared_key)
        management_logs.log_message('Key Management -> Encrypting data with symmetric key')
        cipher = Cipher(algorithms.AES(shared_key_bytes), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()
        management_logs.log_message('Key Management -> Data encrypted with symmetric key')

        management_logs.log_message(f'Key Management -> Encrypting symmetric key with public key for agent {id_agent}')
        encrypted_key = public_key.encrypt(
            shared_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        management_logs.log_message(f'Key Management -> Symmetric key encrypted with public key for agent {id_agent}')

        iv_base64 = base64.b64encode(iv).decode()
        encrypted_data_base64 = base64.b64encode(encrypted_data).decode()
        encrypted_key_base64 = base64.b64encode(encrypted_key).decode()

        management_logs.log_message(f'Key Management -> Data encrypted with hybrid encryption for agent {id_agent}')

        return {
            "iv": iv_base64,
            "data": encrypted_data_base64,
            "key": encrypted_key_base64,
            "id": id_agent
        }
    except Exception as e:
        management_logs.log_message(f"Error encrypting data with public key for agent {id_agent}: {e}")
        return None


def decrypt_data_with_private_key(encrypted_key, iv, encrypted_data, private_key: rsa.RSAPrivateKey, management_logs: ManagementLogs):
    management_logs.log_message('Key Management -> Decrypting data with private key')
    encrypted_key = base64.b64decode(encrypted_key)
    iv = base64.b64decode(iv)
    encrypted_data = base64.b64decode(encrypted_data)

    management_logs.log_message('Key Management -> Decrypting symmetric key with private key')
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    management_logs.log_message('Key Management -> Symmetric key decrypted with private key')

    management_logs.log_message('Key Management -> Decrypting data with symmetric key')
    cipher = Cipher(algorithms.AES(decrypted_key[:32]), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    management_logs.log_message('Key Management -> Data decrypted with symmetric key')

    return decrypted_data
