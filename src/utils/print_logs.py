import tabulate


def print_agents(agents):
    headers = ["ID", "Name", "IP", "Description", "Skills", "Time"]
    agent_data = []
    for id_gent, agent in agents.items():
        agent_data.append([agent['id'], agent['name'], agent['ip'], agent['description'], agent['skills'], agent['time']])
    print(tabulate.tabulate(agent_data, headers=headers))
