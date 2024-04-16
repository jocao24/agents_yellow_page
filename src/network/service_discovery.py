import socket
import Pyro4

from src.manage_logs import ManagementLogs
from src.security.key_management import encrypt_data_with_public_key


def get_host_name(ip_address, management_logs: ManagementLogs):
    try:
        host_name = socket.gethostbyaddr(ip_address)[0]
        return host_name
    except Exception as e:
        management_logs.log_message(f"ServiceDiscovery -> Error al obtener el nombre del host para la IP {ip_address}: {e}")
        return None


def locate_agent(service_name, nameserver: Pyro4.Proxy, management_logs: ManagementLogs):
    management_logs.log_message(f"ServiceDiscovery -> Locating the service {service_name}")
    try:
        service_uri = nameserver.lookup(service_name)
        management_logs.log_message(f"ServiceDiscovery -> Service {service_name} located at {service_uri}")
        return service_uri
    except Exception as e:
        management_logs.log_message(f"ServiceDiscovery -> Error locating the service {service_name}: {e}")
        return None


def send_list_agents(agents: dict, keys_asimetrics: dict, nameserver: Pyro4.Proxy, management_logs: ManagementLogs):
    management_logs.log_message("ServiceDiscovery -> Sending list of agents")
    try:
        if agents != {} and len(agents) > 1:
            list_agents_dict = {}
            for k, v in agents.items():
                list_agents_dict[v['id']] = {
                    'name': v['name'],
                    'description': v['description'],
                    'skills': v['skills'],
                    'public_key': v['public_key'],
                    'id': v['id'],
                    'is_client': v['is_client']
                }
            management_logs.log_message("ServiceDiscovery -> List of agents uploaded successfully")
            management_logs.log_message("ServiceDiscovery -> Sending list of agents to all agents...")

            for k, v in agents.items():
                public_key_agent = keys_asimetrics[v['id']]["public_key_agent"]
                try:
                    management_logs.log_message(f"ServiceDiscovery -> Sending list of agents to agent {v['id']}")
                    management_logs.log_message(f"ServiceDiscovery -> The directory to be sent to the agent {v['id']} is encrypted using hybrid encryption")
                    data_encrypted = encrypt_data_with_public_key(public_key_agent, list_agents_dict, k, management_logs)
                    management_logs.log_message(f"ServiceDiscovery -> Data encrypted successfully for agent {v['id']}")
                    agent_uri = locate_agent(v['id'], nameserver, management_logs)
                    management_logs.log_message(f"ServiceDiscovery -> Agent {v['id']} located at {agent_uri}")
                    agent_proxy = Pyro4.Proxy(agent_uri)
                    management_logs.log_message(f"ServiceDiscovery -> Proxy created for agent {v['id']}")
                    management_logs.log_message(f"ServiceDiscovery -> Sending list of agents to agent {v['id']}")
                    agent_proxy.receive_list_agents(data_encrypted)
                except Exception as e:
                    management_logs.log_message(f"ServiceDiscovery -> Error sending list of agents to agent {v['id']}: {e}")
                    continue

    except Exception as e:
        management_logs.log_message(f"ServiceDiscovery -> Error sending list of agents: {e}")
