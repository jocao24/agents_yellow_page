import socket
import Pyro4

from src.manage_logs_v_2 import ManagementLogs, ComponentType, LogType
from src.security.key_management import encrypt_data_with_public_key


def get_host_name(ip_address, management_logs: ManagementLogs):
    try:
        host_name = socket.gethostbyaddr(ip_address)[0]
        return host_name
    except Exception as e:
        management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Error al obtener el nombre del host para la IP {ip_address}: {e}", LogType.ERROR, False)
        return None


def locate_agent(service_name, nameserver: Pyro4.Proxy, management_logs: ManagementLogs):
    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Locating the service {service_name}", LogType.QUERY, True)
    try:
        service_uri = nameserver.lookup(service_name)
        management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Service {service_name} located at {service_uri}", LogType.QUERY, True)
        return service_uri
    except Exception as e:
        management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Error locating the service {service_name}: {e}", LogType.ERROR, False)
        return None


def send_list_agents(agents: dict, keys_asimetrics: dict, nameserver: Pyro4.Proxy, management_logs: ManagementLogs):
    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, "Sending list of agents", LogType.REQUEST, True)
    try:
        if agents and len(agents) > 1:
            list_agents_dict = {v['id']: {
                'name': v['name'],
                'description': v['description'],
                'skills': v['skills'],
                'public_key': v['public_key'],
                'id': v['id'],
                'is_client': v['is_client']
            } for v in agents.values()}
            
            management_logs.log_message(ComponentType.SERVICE_DISCOVERY, "List of agents uploaded successfully", LogType.UPLOAD, True)
            management_logs.log_message(ComponentType.SERVICE_DISCOVERY, "Sending list of agents to all agents...", LogType.REQUEST, True)

            for k, v in agents.items():
                public_key_agent = keys_asimetrics[v['id']]["public_key_agent"]
                try:
                    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Sending list of agents to agent {v['id']}", LogType.REQUEST, True)
                    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"The directory to be sent to the agent {v['id']} is encrypted using hybrid encryption", LogType.ENCRYPTION, True)
                    data_encrypted = encrypt_data_with_public_key(public_key_agent, list_agents_dict, k, management_logs)
                    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Data encrypted successfully for agent {v['id']}", LogType.ENCRYPTION, True)
                    agent_uri = locate_agent(v['id'], nameserver, management_logs)
                    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Agent {v['id']} located at {agent_uri}", LogType.CONNECTION, True)
                    agent_proxy = Pyro4.Proxy(agent_uri)
                    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Proxy created for agent {v['id']}", LogType.CONNECTION, True)
                    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Sending list of agents to agent {v['id']}", LogType.REQUEST, True)
                    agent_proxy.receive_list_agents(data_encrypted)
                except Exception as e:
                    management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Error sending list of agents to agent {v['id']}: {e}", LogType.ERROR, False)
                    continue

    except Exception as e:
        management_logs.log_message(ComponentType.SERVICE_DISCOVERY, f"Error sending list of agents: {e}", LogType.ERROR, False)
