import os
from Pyro4.util import json


class ManageDataYellowPage:
    def save_data_yp(self, ip_name_server: str):
        data = {
            "ip_name_server": ip_name_server
        }
        if not os.path.exists('data'):
            os.makedirs('data')
        with open('data/yp_data.json', 'w') as file:
            json.dump(data, file)

    def get_data_yp(self) -> str:
        try:
            with open(f'data/yp_data.json', 'r') as file:
                data = json.load(file)
                return data['ip_name_server']
        except FileNotFoundError:
            return None
