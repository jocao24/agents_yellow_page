import Pyro4

from domain.class_for_yp.manage_data_yp import ManageDataYellowPage
from utils.helpers import *
from logs.logs import print_agents
from utils.types.agent_server_type import AgentServerType
from utils.types.client_server_type import ClientServerType


@Pyro4.expose
class YellowPage(object):
    def __init__(self, nameserver):
        self.agents = {}
        self.nameserver = nameserver

    @Pyro4.expose
    def register_agent(self, data_agent: AgentServerType):
        if data_agent['id'] in self.agents:
            return

        self.agents[data_agent['id']] = {
            'id': data_agent['id'],
            'time': get_datetime(),
            'ip': data_agent['ip_agent'],
            'name': data_agent['name'],
            'description': data_agent['description'],
            'skills': data_agent['skills'],
        }
        print_agents(self.agents)

    @Pyro4.expose
    def get_skills(self):
        skills = []
        for agent in self.agents:
            skills.extend(self.agents[agent]['skills'])
        return list(set(skills))

    @Pyro4.expose
    def execute_operation(self, skill, num1, num2):
        try:
            agent_name = None
            for agent in self.agents:
                if skill in self.agents[agent]['skills']:
                    agent_name = self.agents[agent]['name']
                    break

            if agent_name is None:
                raise ValueError("No hay agente disponible para la operación: " + skill)

            lokup_name = self.nameserver.lookup(agent_name)
            print("lookup_name: ", lokup_name)
            proxy_agent = Pyro4.Proxy(lokup_name)
        except KeyError:
            raise ValueError("Operación desconocida: " + skill)
        except Pyro4.errors.NamingError:
            raise ValueError("No hay agente disponible para la operación: " + skill)
        result = proxy_agent.perform_operation(num1, num2)
        return result

