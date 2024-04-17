import base64
import copy
import threading
import Pyro4
from Pyro4.util import json
from src.agent_management import AgentManager
from src.manage_data import get_all_agents_registered, register_agents
from src.manage_logs import ManagementLogs
from src.network.service_discovery import send_list_agents
from src.security.data_management import DataManagement
from src.security.key_management import (
    serialize_public_key,
    encrypt_data_with_public_key,
    decrypt_data_with_private_key,
    generate_keys_asimetrics,
    load_public_key,
    serialize_and_encode_public_key,
    serialize_and_encode_private_key,
    load_public_key_from_base64,
    load_private_key_from_base64
)
from src.security.symmetric_cryptography import decrypt_data_symetric_key
from src.utils.helpers import get_datetime


class YellowPage(AgentManager, object):
    def __init__(self, nameserver: Pyro4.Proxy, ip_ns: str, management_logs: ManagementLogs):
        super().__init__(ip_ns, management_logs)
        self.management_logs = management_logs
        self.management_logs.log_message('YellowPage Remote Object -> Initializing')
        self.ip_ns = ip_ns
        self.nameserver = nameserver
        self.server_uri = None
        self.shared_key_hash = None
        data_management_instance = DataManagement()
        data_saved = data_management_instance.load()
        ultimate_shared_key = data_saved['data_ultimate_connection']['ultimate_shared_key_with_ns']
        self.shared_key = ultimate_shared_key if ultimate_shared_key else self.generate_shared_key()
        self.shared_key_hash = self.generate_shared_key_hash(self.shared_key)
        data_saved['data_ultimate_connection']['ultimate_shared_key_with_ns'] = self.shared_key
        data_management_instance.save(data_saved)
        self.agents = {}
        self.keys_asimetrics = {}
        self.report_status_completed = threading.Event()
        self.management_logs.log_message(
            'YellowPage Remote Object -> Uploading agents registered in the end of the last session')
        self.agents = get_all_agents_registered()
        self.management_logs.log_message('YellowPage Remote Object -> Agents uploaded successfully')

        self.management_logs.log_message('YellowPage Remote Object -> Initialized')
        self.management_logs.log_message('YellowPage Remote Object -> Initializing monitoring thread')
        self.start_monitoring()

    @Pyro4.expose
    def request_register(self, request: dict):
        id_agent = request["id"]
        ip = Pyro4.current_context.client_sock_addr[0]
        self.management_logs.log_message(f"YellowPage Remote Object -> {id_agent} - {ip} - Requesting registration")
        self.management_logs.log_message(
            f"YellowPage Remote Object -> {id_agent} - {ip} - Decrypting request sent by the Deamon")
        data_decrypted = decrypt_data_symetric_key(self.shared_key_hash, request["iv"], request["data"],
                                                   self.management_logs)
        self.management_logs.log_message(
            f"YellowPage Remote Object -> {id_agent} - {ip} - Request decrypted successfully")

        code_otp = data_decrypted["code_totp"]
        shared_key_ns_agent = data_decrypted["shared_key"]
        key_desencrypted = (ip + code_otp + id_agent + code_otp + shared_key_ns_agent + ip + id_agent +
                            shared_key_ns_agent + code_otp)
        key_hash = self.hash_key(key_desencrypted)

        self.management_logs.log_message(
            f"YellowPage Remote Object -> {id_agent} - {ip} - Decrypting data sent by the Agent")
        data_decrypted_yp = decrypt_data_symetric_key(key_hash, data_decrypted["data_cifrated_yp"]["iv"],
                                                      data_decrypted["data_cifrated_yp"]["data"], self.management_logs)
        self.management_logs.log_message(f"YellowPage Remote Object -> {id_agent} - {ip} - Data decrypted successfully")
        public_key_agent = load_public_key(data_decrypted_yp["public_key"], self.management_logs)
        private_key, public_key = generate_keys_asimetrics(self.management_logs)
        public_key_serialized = serialize_public_key(public_key, self.management_logs)
        self.keys_asimetrics[id_agent] = {
            "public_key_agent": public_key_agent,
            "private_key_generated": private_key,
            "public_key_generated": public_key_serialized
        }
        self.management_logs.log_message(
            f"YellowPage Remote Object -> {id_agent} - {ip} - Successfully generated the asymmetric keys")

    @Pyro4.expose
    def get_access_data_for_register(self, id_agent: str):
        self.management_logs.log_message(
            f"YellowPage Remote Object -> {id_agent} - Requesting access data for registration")
        public_key_generated = self.keys_asimetrics[id_agent]["public_key_generated"]
        public_key_generated = base64.b64encode(public_key_generated).decode()
        public_key_agent = self.keys_asimetrics[id_agent]["public_key_agent"]
        server_uri_base64 = str(self.server_uri)
        self.management_logs.log_message(f"YellowPage Remote Object -> {id_agent} - Access data requested successfully")
        return encrypt_data_with_public_key(public_key_agent, {
            "public_key": public_key_generated,
            "server_uri": server_uri_base64
        }, id_agent, self.management_logs)

    @Pyro4.expose
    def register_agent(self, request):
        try:
            ip = Pyro4.current_context.client_sock_addr[0]
            id_agent = request.get("id")
            self.management_logs.log_message(f"YellowPage Remote Object -> {id_agent} - {ip} - Registering agent")

            iv = request.get("iv")
            data_encripted = request.get("data")
            key = request.get("key")

            self.management_logs.log_message(
                f"YellowPage Remote Object -> {id_agent} - {ip} - Decrypting data sent by the agent")
            private_key = self.keys_asimetrics[id_agent]["private_key_generated"]
            decrypted_data = decrypt_data_with_private_key(key, iv, data_encripted, private_key, self.management_logs)
            decrypted_data_dict = json.loads(decrypted_data.decode("utf-8"))
            self.management_logs.log_message(
                f"YellowPage Remote Object -> {id_agent} - {ip} - Data decrypted successfully")

            public_key = serialize_and_encode_public_key(self.keys_asimetrics[id_agent]['public_key_agent'],
                                                         self.management_logs)
            private_key = self.keys_asimetrics[id_agent]["private_key_generated"]
            private_key_serialized = serialize_and_encode_private_key(private_key, self.management_logs)
            public_key_pem = self.keys_asimetrics[id_agent]["public_key_generated"]
            public_key_base64 = base64.b64encode(public_key_pem).decode('utf-8')

            self.agents[id_agent] = {
                'id': id_agent,
                'time': str(get_datetime()),
                'ip': Pyro4.current_context.client_sock_addr[0],
                'name': decrypted_data_dict['name'],
                'description': decrypted_data_dict['description'],
                'skills': decrypted_data_dict['skills'],
                'public_key': public_key,
                'is_client': decrypted_data_dict.get('is_client', False),
                'is_provider': decrypted_data_dict.get('is_provider', False),
                'is_consumer': decrypted_data_dict.get('is_consumer', False),
                'keys_asymetrics': {
                    'public_key': public_key_base64,
                    'private_key': private_key_serialized
                }
            }
            self.management_logs.log_message(
                f"YellowPage Remote Object -> {id_agent} - {ip} - Agent registered successfully")
            self.management_logs.log_message(
                f"YellowPage Remote Object -> {id_agent} - {ip} - Saving the agent in the data file")
            register_agents(self.agents)
            return True
        except Exception as e:
            self.management_logs.log_message(f"Error registering agent: {e}")
            return False

    @Pyro4.expose
    def ping(self, iv, data):
        self.management_logs.log_message("YellowPage Remote Object -> Ping")
        try:
            self.management_logs.log_message("YellowPage Remote Object -> Decrypting data")
            data_decrypted = decrypt_data_symetric_key(self.shared_key_hash, iv, data, self.management_logs)
            self.management_logs.log_message("YellowPage Remote Object -> Data decrypted successfully")
            message = str(data_decrypted["message"]).encode()
            return {
                "message": "pong",
                "message_send": message
            }

        except Exception as e:
            self.management_logs.log_message(f"Ping Error: {e}")
            return {
                "message": "Shared key is not correct "
            }

    def start_monitoring(self):
        def monitor():
            previous_agent_ids = set()
            while True:
                agents_active = self.verify_agents_availability()
                current_agent_ids = set(get_all_agents_registered().keys())
                if current_agent_ids != previous_agent_ids or agents_active != []:
                    send_list_agents(self.agents, self.keys_asimetrics, self.nameserver, self.management_logs)
                    if self.agents != {}:
                        register_agents(self.agents)

                previous_agent_ids = copy.deepcopy(current_agent_ids)
                threading.Event().wait(5)

        monitoring_thread = threading.Thread(target=monitor)
        monitoring_thread.daemon = True
        monitoring_thread.start()

    @Pyro4.expose
    def verify_agents_availability(self):
        unavailable_agents = []
        for id_agent, agent_info in list(self.agents.items()):
            try:
                lookup = self.nameserver.lookup(id_agent)
                agent_proxy = Pyro4.Proxy(lookup)
                agent_proxy._pyroTimeout = 2
                agent_proxy.ping()
            except Exception as e:
                self.management_logs.log_message(f"Agent {id_agent} is not available: {e}")
                unavailable_agents.append(id_agent)

        for id_agent in unavailable_agents:
            if id_agent in self.agents:
                self.management_logs.log_message(f"Removing agent {id_agent} from the list of agents")
                del self.agents[id_agent]

            if id_agent in self.keys_asimetrics:
                del self.keys_asimetrics[id_agent]

        self.keys_asimetrics = {}
        for id_agent, agent_info in self.agents.items():
            if 'keys_asymetrics' in agent_info:
                public_key_generated = load_public_key_from_base64(agent_info['keys_asymetrics']['public_key'])
                private_key_generated = load_private_key_from_base64(agent_info['keys_asymetrics']['private_key'])
                public_key_agent = load_public_key_from_base64(agent_info['public_key'])
                self.keys_asimetrics[id_agent] = {
                    "public_key_agent": public_key_agent,
                    "private_key_generated": private_key_generated,
                    "public_key_generated": public_key_generated
                }
        return unavailable_agents
