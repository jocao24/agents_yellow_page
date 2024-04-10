import datetime

from src.security.data_management import DataManagement


def log_message(message) -> str:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"

    # Cargar los datos actuales
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()

    # Agregar el nuevo mensaje de log
    current_data['logs'] += log_entry

    # Guardar los datos actualizados
    data_management_instance.save(current_data)

    return log_entry


def start_new_session_log():
    session_start = "\n===== New Session Started =====\n"

    # Cargar los datos actuales
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()

    # Agregar marca de inicio de sesión
    current_data['logs'] += session_start

    # Guardar los datos actualizados
    data_management_instance.save(current_data)


def get_end_session_log():
    with open("yellow_page_logs.txt", "r") as log_file:
        logs = log_file.read()
        logs = logs.split("===== New Session Started =====")
        return logs[-2]


def get_all_logs():
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()

    return current_data['logs']


def register_agents(data_agents: dict):
    # Cargar los datos actuales
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()

    # Actualizar los datos de los agentes
    # Asegúrate de que 'data_agents' esté en el formato correcto para ser almacenado
    current_data['angents_data'] = data_agents

    # Guardar los datos actualizados
    data_management_instance.save(current_data)


def get_all_agents_registered() -> dict:
    # Cargar los datos actuales
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()

    return current_data['angents_data']


