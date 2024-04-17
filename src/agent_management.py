import secrets
import socket
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from src.manage_logs import ManagementLogs
from src.utils.get_ip import get_ip


class AgentManager:
    def __init__(self, ip_ns: str, management_logs: ManagementLogs):
        self.management_logs = management_logs
        self.management_logs.log_message('AgentManager initialized')
        self.agents = {}
        self.keys_asimetrics = {}
        self.shared_key_hash = None
        self.ip_ns = ip_ns

    def hash_key(self, key: str):
        self.management_logs.log_message('AgentManager -> Hashing key')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key.encode())
        hash_value = digest.finalize()
        self.management_logs.log_message('AgentManager -> Key hashed')
        return hash_value

    def get_name_device(self, ip: str):
        try:
            name = socket.gethostbyaddr(ip)
            return name[0]
        except Exception as e:
            self.management_logs.log_message(f"An error occurred while trying to get the name of the device: {e}")
            return None

    def verify_shared_key(self, shared_key_hash):
        self.management_logs.log_message('AgentManager -> Verifying shared key')
        result = shared_key_hash == self.shared_key_hash
        self.management_logs.log_message(f'AgentManager -> Shared key verified: {result}')

    def generate_shared_key_hash(self, shared_key: str, name_device: str):
        self.management_logs.log_message('AgentManager -> Generating shared key hash')
        shared_key_complete = (shared_key + get_ip() + self.ip_ns + shared_key + name_device +
                               shared_key + self.ip_ns + get_ip())
        self.shared_key_hash = self.hash_key(shared_key_complete)
        self.management_logs.log_message('AgentManager -> Shared key hash generated')
        return self.shared_key_hash

    def generate_shared_key(self):
        key_length = 6
        characters = string.ascii_letters + string.digits
        shared_key = "".join(secrets.choice(characters) for _ in range(key_length))
        return shared_key
