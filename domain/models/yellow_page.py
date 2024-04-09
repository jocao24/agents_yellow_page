import base64
import threading
import Pyro4
from Pyro4.util import json
from domain.agent_management import AgentManager
from manage_logs.manage_logs import log_message
from network.service_discovery import send_list_agents
from security.key_management import serialize_public_key, encrypt_data_with_public_key, decrypt_data_with_private_key, \
    generate_keys_asimetrics, load_public_key, generate_public_key
from security.symmetric_cryptography import decrypt_data_symetric_key
from utils.helpers import get_datetime


class YellowPage(AgentManager, object):
    def __init__(self, nameserver: Pyro4.Proxy, ip_ns: str):
        super().__init__(ip_ns)
        self.ip_ns = ip_ns
        self.nameserver = nameserver
        self.server_uri = None
        self.shared_key_hash = None
        self.shared_key = self.generate_shared_key()
        self.agents = {}
        self.proxies_agents = None
        self.keys_asimetrics = {}
        self.report_status_completed = threading.Event()

    @Pyro4.expose
    def request_register(self, request: dict):
        id_agent = request["id"]
        ip = Pyro4.current_context.client_sock_addr[0]
        log_message("Register request from: " + str(ip))

        data_decrypted = decrypt_data_symetric_key(self.shared_key_hash, request["iv"], request["data"])
        code_otp = data_decrypted["code_totp"]
        shared_key_ns_agent = data_decrypted["shared_key"]

        key_desencrypted = (ip + code_otp + id_agent + code_otp + shared_key_ns_agent + ip + id_agent +
                            shared_key_ns_agent + code_otp)
        key_hash = self.hash_key(key_desencrypted)
        data_decrypted_yp = decrypt_data_symetric_key(key_hash, data_decrypted["data_cifrated_yp"]["iv"], data_decrypted["data_cifrated_yp"]["data"])

        public_key_agent = load_public_key(data_decrypted_yp["public_key"])
        private_key, public_key = generate_keys_asimetrics()
        public_key_serialized = serialize_public_key(public_key)
        self.keys_asimetrics[id_agent] = {
            "public_key_agent": public_key_agent,
            "private_key_generated": private_key,
            "public_key_generated": public_key_serialized
        }

    @Pyro4.expose
    def get_access_data_for_register(self, id_agent: str):
        public_key_generated = self.keys_asimetrics[id_agent]["public_key_generated"]
        public_key_generated = base64.b64encode(public_key_generated).decode()
        public_key_agent = self.keys_asimetrics[id_agent]["public_key_agent"]
        server_uri_base64 = str(self.server_uri)
        return encrypt_data_with_public_key(public_key_agent, {
            "public_key": public_key_generated,
            "server_uri": server_uri_base64
        }, id_agent)

    @Pyro4.expose
    def register_agent(self, request):
        try:
            id_agent = request.get("id")
            iv = request.get("iv")
            data_encripted = request.get("data")
            key = request.get("key")

            private_key = self.keys_asimetrics[id_agent]["private_key_generated"]
            # Se desencripta la clave privada del agente
            decrypted_data = decrypt_data_with_private_key(key, iv, data_encripted, private_key)
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
        post_action_thread = threading.Thread(target=self.__handle_post_report_status)
        post_action_thread.daemon = True
        post_action_thread.start()

    def __handle_post_report_status(self):
        threading.Timer(0.02, send_list_agents, args=(self.agents, self.keys_asimetrics, self.nameserver)).start()

    @Pyro4.expose
    def ping(self, iv, data):
        try:
            data_decrypted = decrypt_data_symetric_key(self.shared_key_hash, iv, data)
            message = str(data_decrypted["message"]).encode()
            return {
                "message": "pong",
                "message_send": message
            }

        except Exception:
            return {
                "message": "Shared key is not correct"
            }
