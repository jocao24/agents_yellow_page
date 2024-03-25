import datetime
from typing import List, Any

from utils.types.agent_server_type import AgentServerType


def log_message(message) -> str:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}"
    with open("yellow_page_logs.txt", "a") as log_file:
        log_file.write(log_entry + "\n")

    return log_entry


def start_new_session_log():
    with open("yellow_page_logs.txt", "a") as log_file:
        log_file.write("\n===== New Session Started =====\n")


def get_end_session_log():
    with open("yellow_page_logs.txt", "r") as log_file:
        logs = log_file.read()
        logs = logs.split("===== New Session Started =====")
        return logs[-2]


def get_all_logs():
    with open("yellow_page_logs.txt", "r") as log_file:
        logs = log_file.read()
        return logs


def register_agents(data_agents: dict):
    for key, value in data_agents.items():
        if value == {}:
            del data_agents[key]

    # Se sobre escribe el archivo con los agentes registrados
    with open("agents_registered.txt", "w") as log_file:
        for key, value in data_agents.items():
            log_file.write(str(value))
            if key != list(data_agents.keys())[-1]:
                log_file.write("\n")


def get_all_agents_registered() -> dict:
    # Vertifica si el archivo existe, si no existe retorna un diccionario vacio
    try:
        with open("agents_registered.txt", "r") as log_file:
            agents = log_file.read()
            agents = agents.split("\n")
            agents = [eval(agent) for agent in agents if agent != '']
            agents = {agent['id']: agent for agent in agents}
            return agents
    except FileNotFoundError:
        return {}



