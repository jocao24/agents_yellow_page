import base64
import socket
import Pyro4
from manage_logs.manage_logs import log_message
from security.key_management import serialize_public_key, encrypt_data_with_public_key


def get_host_name(ip_address):
    try:
        host_name = socket.gethostbyaddr(ip_address)[0]
        return host_name
    except Exception as e:
        log_message(f"Error al obtener el nombre del host para la IP {ip_address}: {e}")
        return None


def locate_agent(service_name, nameserver: Pyro4.Proxy):
    try:
        service_uri = nameserver.lookup(service_name)
        return service_uri
    except Exception as e:
        log_message(f"Error locating the service {service_name}: {e}")
        return None


def send_list_agents(agents: dict, keys_asimetrics: dict, nameserver: Pyro4.Proxy):
    try:
        if agents != {} and len(agents) > 1:
            list_agents_dict = {}
            for k, v in agents.items():
                public_key_serialized = serialize_public_key(v['public_key'])
                public_key_cod = base64.b64encode(public_key_serialized).decode()
                list_agents_dict[v['id']] = {
                    'name': v['name'],
                    'description': v['description'],
                    'skills': v['skills'],
                    'public_key': public_key_cod,
                    'id': v['id'],
                    'is_client': v['is_client']
                }

            for k, v in agents.items():
                public_key_agent = keys_asimetrics[k]["public_key_agent"]
                data_encrypted = encrypt_data_with_public_key(public_key_agent, list_agents_dict, k)
                agent_uri = locate_agent(v['id'], nameserver)
                agent_proxy = Pyro4.Proxy(agent_uri)
                agent_proxy.receive_list_agents(data_encrypted)

    except Exception as e:
        print(f"Error: {e}")

