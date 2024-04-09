import secrets
import socket
import string

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from manage_logs.manage_logs import log_message
from utils.get_ip import get_ip


class AgentManager:
    def __init__(self, ip_ns: str):
        self.agents = {}
        self.keys_asimetrics = {}
        self.shared_key_hash = None
        self.ip_ns = ip_ns

    def generate_private_key(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_public_key(self, private_key: rsa.RSAPrivateKey):
        return private_key.public_key()

    def serialize_public_key(self, public_key: rsa.RSAPublicKey):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serialize_private_key(self, private_key: rsa.RSAPrivateKey):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key_generated_for_agent(self, id_agent: str):
        return self.keys_asimetrics[id_agent]

    def hash_key(self, key: str):
        # Crea una instancia del digest de hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

        # Pasa los datos a hashear (necesitan estar en bytes)
        digest.update(key.encode())

        # Finaliza el proceso de hash y obtiene el valor hash resultante
        hash_value = digest.finalize()

        return hash_value

    def get_name_device(self, ip: str):
        try:
            name = socket.gethostbyaddr(ip)
            return name[0]
        except Exception as e:
            log_message(f"An error occurred while trying to get the name of the device: {e}")
            return None

    def verify_shared_key(self, shared_key_hash):
        return shared_key_hash == self.shared_key_hash

    def generate_shared_key(self):
        key_length = 6
        # Combinar letras y números para la clave
        characters = string.ascii_letters + string.digits
        # Generar la clave
        shared_key = "".join(secrets.choice(characters) for _ in range(key_length))
        shared_key_complete = (shared_key + get_ip() + self.ip_ns + shared_key + self.get_name_device(self.ip_ns) +
                               shared_key + self.ip_ns + get_ip())
        self.shared_key_hash = self.hash_key(shared_key_complete)
        return shared_key


