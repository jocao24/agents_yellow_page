import tabulate


def print_agents(agents):
    headers = ["ID", "Name", "IP", "Description", "Skills", "Time"]
    agent_data = []
    for id_agent, agent in agents.items():
        agent_data.append([agent['id'], agent['name'], agent['ip'], agent['description'], agent['skills'], agent['time']])
    print(tabulate.tabulate(agent_data, headers=headers))


def print_agents_aviality(agents):
    headers = ["ID", "Name", "IP", "Description", "Skills", "Time", "Active"]
    agent_data = []
    for id_agent, agent in agents.items():
        active_status = "Yes" if agent.get('active', True) else "No"
        if active_status == "No":
            continue
        agent_data.append([agent['id'], agent['name'], agent['ip'], agent['description'], agent['skills'], agent['time']])
    print(tabulate.tabulate(agent_data, headers=headers))
