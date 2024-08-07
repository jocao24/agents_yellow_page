import os
from src.security.secure_storage import SecureStorage
from src.utils.get_system_uuid import get_system_uuid
from src.types.save_data_type import SaveDataType


class DataManagement:
    _instance = None

    # Obtén la ruta del directorio actual (el que contiene el script que se está ejecutando)
    _current_dir = os.path.dirname(os.path.abspath(__file__))

    # Navega un nivel hacia atrás para ubicarte en el directorio que contiene 'src'
    _project_root = os.path.abspath(os.path.join(_current_dir, os.pardir, os.pardir))

    # Concatena la carpeta 'data' a la ruta del proyecto
    _data_dir = os.path.join(_project_root, 'data') + os.sep

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(DataManagement, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.file_path = f'{self._data_dir}data_yp.enc'
            self.secure_storage = SecureStorage(get_system_uuid().encode(), self.file_path)
            self._ensure_file_exists()
            self.initialized = True

    def _ensure_file_exists(self):
        if not os.path.exists(self.file_path):
            self.save({
                'logs': '',
                'data_ultimate_connection': {'ip_ultimate_ns': '', 'ultimate_shared_key_with_ns': ''},
                'angents_data': {}
            })

    def save(self, data: SaveDataType):
        data_for_storage = {
            'logs': data['logs'],
            'data_ultimate_connection': data['data_ultimate_connection'],
            'angents_data': data['angents_data']
        }
        self.secure_storage.encrypt_data(data_for_storage)

    def load(self) -> SaveDataType:
        logs = ''
        data_ultimate_connection = {'ip_ultimate_ns': '', 'ultimate_shared_key_with_ns': ''}
        angents_data = {}
        try:
            data_from_storage = self.secure_storage.decrypt_data()
            logs = data_from_storage['logs']
            data_ultimate_connection = data_from_storage['data_ultimate_connection']
            angents_data = data_from_storage['angents_data']
        except Exception as e:
            print(f"Error loading data: {e}")
        return {
            'logs': logs,
            'data_ultimate_connection': data_ultimate_connection,
            'angents_data': angents_data
        }
