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
            for k, current_agent in agents.items():
                # Crear un nuevo diccionario que incluye todos los agentes excepto el actual (current_agent['id'])
                list_agents_dict = {
                    agent_id: {
                        'name': details['name'],
                        'description': details['description'],
                        'skills': details['skills'],
                        'public_key': details['public_key'],
                        'id': details['id'],
                        'is_client': details['is_client']
                    }
                    for agent_id, details in agents.items() if agent_id != current_agent['id']
                }

                public_key_agent = keys_asimetrics[current_agent['id']]["public_key_agent"]
                try:
                    management_logs.log_message(
                        f"ServiceDiscovery -> Sending list of agents to agent {current_agent['id']}")
                    management_logs.log_message(
                        f"ServiceDiscovery -> The directory to be sent to the agent {current_agent['id']} is encrypted using hybrid encryption")

                    # Encrypt data excluding the current agent
                    data_encrypted = encrypt_data_with_public_key(public_key_agent, list_agents_dict,
                                                                  current_agent['id'], management_logs)
                    management_logs.log_message(
                        f"ServiceDiscovery -> Data encrypted successfully for agent {current_agent['id']}")

                    agent_uri = locate_agent(current_agent['id'], nameserver, management_logs)
                    management_logs.log_message(
                        f"ServiceDiscovery -> Agent {current_agent['id']} located at {agent_uri}")

                    agent_proxy = Pyro4.Proxy(agent_uri)
                    management_logs.log_message(f"ServiceDiscovery -> Proxy created for agent {current_agent['id']}")
                    management_logs.log_message(
                        f"ServiceDiscovery -> Sending list of agents to agent {current_agent['id']}")

                    agent_proxy.receive_list_agents(data_encrypted)
                except Exception as e:
                    management_logs.log_message(
                        f"ServiceDiscovery -> Error sending list of agents to agent {current_agent['id']}: {e}")
                    continue

    except Exception as e:
        management_logs.log_message(f"ServiceDiscovery -> Error sending list of agents: {e}")
