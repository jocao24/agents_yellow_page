import base64
import secrets
import socket
import string
import threading
from os import urandom

import time
from typing import TypedDict

import Pyro4
from Pyro4.util import json
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from domain.class_for_yp.manage_data_yp import ManageDataYellowPage
from manage_logs.manage_logs import log_message, register_agents, get_all_agents_registered
from utils.get_ip import get_ip
from utils.helpers import *
from logs.logs import print_agents
from utils.types.agent_server_type import AgentServerType
from utils.types.client_server_type import ClientServerType


class DataEncriptedType(TypedDict):
    iv: str
    data: str


class DataEncriptedGatewayType(TypedDict):
    id: str
    ip: str
    data: str
    iv: str


class DataDecryptedType(TypedDict):
    skills: list[str]
    name: str
    description: str
    public_key: str


class YellowPage(object):
    def __init__(self, nameserver: Pyro4.Proxy, ip_ns: str):
        self.ip_ns = ip_ns
        self.nameserver = nameserver
        self.server_uri = None
        self.shared_key_hash = None
        self.shared_key = self.generate_shared_key()
        self.agents = {}
        self.proxies_agents = None
        self.keys_asimetrics = {}
        self.report_status_completed = threading.Event()


    def get_name_device(self, ip: str):
        try:
            name = socket.gethostbyaddr(ip)
            return name[0]
        except Exception as e:
            log_message(f"An error occurred while trying to get the name of the device: {e}")
            return None

    def generate_shared_key(self):
        key_length = 6
        # Combinar letras y números para la clave
        characters = string.ascii_letters + string.digits
        # Generar la clave
        shared_key = "".join(secrets.choice(characters) for _ in range(key_length))
        # Retornar la clave generada
        # key_shared_com = key_shared + self.ip_yp + get_ip() + key_shared + self.get_name_device(get_ip()) + key_shared
        shared_key_complete = shared_key + get_ip() + self.ip_ns + shared_key + self.get_name_device(self.ip_ns) + shared_key
        self.shared_key_hash = self.hash_key(shared_key_complete)
        return shared_key

    def hash_key(self, key: str):
        key_complete = key + self.ip_ns + get_ip()

        # Crea una instancia del digest de hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

        # Pasa los datos a hashear (necesitan estar en bytes)
        digest.update(key_complete.encode())

        # Finaliza el proceso de hash y obtiene el valor hash resultante
        hash_value = digest.finalize()

        return hash_value

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

    def verify_shared_key(self, shared_key_hash):
        return shared_key_hash == self.shared_key_hash

    @Pyro4.expose
    def request_register(self, data):
        id_agent = data["id"]
        ip = Pyro4.current_context.client_sock_addr[0]
        log_message("Register request from: " + str(ip))
        iv_base64 = data["iv"]
        data_base64 = data["data"]

        iv = base64.b64decode(iv_base64)
        data = base64.b64decode(data_base64)

        # Se descifra el iv y los datos
        cipher = Cipher(algorithms.AES(self.shared_key_hash[:32]), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()

        data_decrypted = json.loads(decrypted_data.decode("utf-8"))
        public_key = str(data_decrypted["public_key"]).encode()

        public_key_agent = serialization.load_pem_public_key(public_key, backend=default_backend())
        # Se le generan 2 claves asimetricas
        private_key = self.generate_private_key()
        public_key = self.generate_public_key(private_key)
        public_key_serialized = self.serialize_public_key(public_key)
        self.keys_asimetrics[id_agent] = {
            "public_key_agent": public_key_agent,
            "private_key_generated": private_key,
            "public_key_generated": public_key_serialized
        }

    @Pyro4.expose
    def get_access_data_for_register(self, id_agent: str):
        public_key_generated = self.keys_asimetrics[id_agent]["public_key_generated"]
        # L convierto a base64 para que pueda ser enviado por la red
        public_key_generated = base64.b64encode(public_key_generated).decode()
        public_key_agent = self.keys_asimetrics[id_agent]["public_key_agent"]
        server_uri_base64 = str(self.server_uri)
        return self.encrypt_data(public_key_agent, {
            "public_key": public_key_generated,
            "server_uri": server_uri_base64
        }, id_agent)

    def generate_shared_key_for_agents(self):
        # Fernet.generate_key() ya devuelve una clave segura que puede ser usada directamente
        return Fernet.generate_key()

    def encrypt_data(self, public_key: rsa.RSAPublicKey, data: dict, id_agent):
        # Convertir los datos a bytes
        data_bytes = json.dumps(data).encode("utf-8")

        # Generar un IV aleatorio
        iv = urandom(16)

        # Generar una clave simétrica segura
        shared_key = self.generate_shared_key_for_agents()

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

    def decrypt_data(self, encrypted_key_base64, iv_base64, encrypted_data_base64, private_key: rsa.RSAPrivateKey):
        # Decode the base64 encoded encrypted AES key, IV, and data
        encrypted_key = base64.b64decode(encrypted_key_base64)
        iv = base64.b64decode(iv_base64)
        encrypted_data = base64.b64decode(encrypted_data_base64)

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

    @Pyro4.expose
    def register_agent(self, request):
        try:
            id_agent = request.get("id")
            iv = request.get("iv")
            data_encripted = request.get("data")
            key = request.get("key")

            private_key = self.keys_asimetrics[id_agent]["private_key_generated"]
            # Se desencripta la clave privada del agente
            decrypted_data = self.decrypt_data(key, iv, data_encripted, private_key)
            decrypted_data_dict = json.loads(decrypted_data.decode("utf-8"))
            print(f"\nData decrypted Agent: \n{data_encripted}")
            self.agents[id_agent] = {
                'id': id_agent,
                'time': get_datetime(),
                'ip': Pyro4.current_context.client_sock_addr[0],
                'name': decrypted_data_dict['name'],
                'description': decrypted_data_dict['description'],
                'skills': decrypted_data_dict['skills'],
                'public_key': self.keys_asimetrics[id_agent]["public_key_agent"],
                'is_client': decrypted_data_dict.get('is_client', False)
            }

            return True
        except Exception as e:
            print(f"Error: {e}")
            return False

    @Pyro4.expose
    def report_status_ok(self):
        # Iniciar un hilo para manejar la acción posterior sin retrasar el retorno de este método
        post_action_thread = threading.Thread(target=self.__handle_post_report_status)
        post_action_thread.daemon = True
        post_action_thread.start()

    def __handle_post_report_status(self):
        threading.Timer(0.02, self.__send_list_agents).start()

    def __send_list_agents(self):
        try:

            if self.agents != {} and len(self.agents) > 1:
                list_agents_dict = {}
                for k, v in self.agents.items():
                    # Error: Object of type RSAPublicKey is not JSON serializable
                    # public_key_generated = base64.b64encode(public_key_generated).decode()
                    public_key_serialized = self.serialize_public_key(v['public_key'])
                    public_key_cod = base64.b64encode(public_key_serialized).decode()
                    # se codif
                    list_agents_dict[v['id']] = {
                        'name': v['name'],
                        'description': v['description'],
                        'skills': v['skills'],
                        'public_key': public_key_cod,
                        'id': v['id'],
                        'is_client': v['is_client']
                    }

                # Se le hace lookup a cada agente para enviarle la lista de agentes
                for k, v in self.agents.items():
                    public_key_agent = self.keys_asimetrics[k]["public_key_agent"]
                    data_encrypted = self.encrypt_data(public_key_agent, list_agents_dict, k)
                    agent = self.nameserver.lookup(v['id'])
                    # Se crea un proxy del agente
                    agent_proxy = Pyro4.Proxy(agent)
                    # Se envia la información al agente
                    agent_proxy.receive_list_agents(data_encrypted)

        except Exception as e:
            print(f"Error: {e}")


    @Pyro4.expose
    def ping(self, iv, data):
        try:
           # Se desencripta el iv y los datos
           iv_base64 = iv
           data_base64 = data
           iv = base64.b64decode(iv_base64)
           data = base64.b64decode(data_base64)

           cipher = Cipher(algorithms.AES(self.shared_key_hash[:32]), modes.CFB(iv), backend=default_backend())
           decryptor = cipher.decryptor()
           decrypted_data = decryptor.update(data) + decryptor.finalize()
           data_decrypted = json.loads(decrypted_data.decode("utf-8"))
           message = str(data_decrypted["message"]).encode()
           # Si llego hasta aca, es porque la key compartida es correcta
           return {
               "message": "pong"
           }

        except Exception as e:
            return {
                "message": "Shared key is not correct"
            }
