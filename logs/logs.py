import tabulate


def print_agents(agents):
    headers = ['id', 'Name', 'IP Address', 'Description', 'Skills', 'Registration Time']
    agent_data = [
        [id, info['name'], info['ip'], info['description'], info['skills'], info['time'].strftime('%Y-%m-%d %H:%M:%S')]
        for id, info in agents.items()]
    print("Summary of Agents:")
    print(tabulate.tabulate(agent_data, headers=headers))
