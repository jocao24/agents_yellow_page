from src.security.data_management import DataManagement


def register_agents(data_agents: dict):
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()
    current_data['angents_data'] = data_agents
    data_management_instance.save(current_data)


def get_all_agents_registered() -> dict:
    data_management_instance = DataManagement()
    current_data = data_management_instance.load()
    return current_data['angents_data']


