import base64
import threading
import Pyro4
from Pyro4.util import json
from src.agent_management import AgentManager
from src.manage_data import log_message, register_agents, get_all_agents_registered
from src.network.service_discovery import send_list_agents
from src.security.data_management import DataManagement
from src.security.key_management import serialize_public_key, encrypt_data_with_public_key, decrypt_data_with_private_key, \
    generate_keys_asimetrics, load_public_key, serialize_and_encode_public_key, serialize_and_encode_private_key, load_public_key_from_base64, \
    load_private_key_from_base64
from src.security.symmetric_cryptography import decrypt_data_symetric_key
from src.utils.helpers import get_datetime


class YellowPage(AgentManager, object):
    def __init__(self, nameserver: Pyro4.Proxy, ip_ns: str):
        super().__init__(ip_ns)
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

        # Inicializar los atributos de agentes y claves asimétricas
        self.agents = {}
        self.keys_asimetrics = {}
        self.report_status_completed = threading.Event()

        # Cargar los agentes registrados previamente
        self.agents = get_all_agents_registered()

        # Si hay agentes registrados, verificar su disponibilidad
        if self.agents:
            self.verify_agents_availability()

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
            public_key = serialize_and_encode_public_key(self.keys_asimetrics[id_agent]['public_key_agent'])

            private_key = self.keys_asimetrics[id_agent]["private_key_generated"]
            private_key_serialized = serialize_and_encode_private_key(private_key)

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
                'keys_asymetrics': {
                    'public_key': public_key_base64,
                    'private_key': private_key_serialized
                }
            }
            register_agents(self.agents)

            return True
        except Exception as e:
            log_message(f"Error registering agent: {e}")
            return False

    @Pyro4.expose
    def report_status_ok(self):
        post_action_thread = threading.Thread(target=self.__handle_post_report_status)
        post_action_thread.daemon = True
        post_action_thread.start()

    def __handle_post_report_status(self):
        threading.Timer(0.05, send_list_agents, args=(self.agents, self.keys_asimetrics, self.nameserver)).start()

    @Pyro4.expose
    def ping(self, iv, data):
        try:
            data_decrypted = decrypt_data_symetric_key(self.shared_key_hash, iv, data)
            message = str(data_decrypted["message"]).encode()
            return {
                "message": "pong",
                "message_send": message
            }

        except Exception as e:
            log_message(f"Ping Error: {e}")
            return {
                "message": "Shared key is not correct "
            }

    @Pyro4.expose
    def verify_agents_availability(self):
        unavailable_agents = []
        for id_agent, agent_info in list(self.agents.items()):
            try:
                lookup = self.nameserver.lookup(id_agent)
                agent_proxy = Pyro4.Proxy(lookup)
                agent_proxy._pyroTimeout = 5  # Tiempo de espera
                agent_proxy.ping()  # Intenta hacer ping al agente
            except Exception as e:
                log_message(f"Agent {id_agent} is not available: {e}")
                # Agente no disponible
                unavailable_agents.append(id_agent)

        # Procesar agentes no disponibles
        for id_agent in unavailable_agents:
            del self.agents[id_agent]  # Elimina el agente del directorio

        self.keys_asimetrics = {}
        for id_agent, agent_info in self.agents.items():
            if 'keys_asymetrics' in agent_info:
                public_key = load_public_key_from_base64(agent_info['keys_asymetrics']['public_key'])
                private_key = load_private_key_from_base64(agent_info['keys_asymetrics']['private_key'])
                self.keys_asimetrics[id_agent] = {
                    'public_key_agent': public_key,
                    'private_key_generated': private_key,
                }

        # Guardar los cambios en los agentes registrados
        register_agents(self.agents)
