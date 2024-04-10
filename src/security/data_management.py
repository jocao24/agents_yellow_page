import os
from src.security.secure_storage import SecureStorage
from src.utils.get_system_uuid import get_system_uuid
from src.types.save_data_type import SaveDataType


class DataManagement:
    _instance = None  # Variable de clase para almacenar la instancia singleton

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(DataManagement, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'initialized'):  # Esto previene la inicialización múltiple
            self.file_path = 'data/data_yp.enc'
            self.secure_storage = SecureStorage(get_system_uuid().encode(), self.file_path)
            self._ensure_file_exists()
            self.initialized = True

    # El resto de tu implementación de DataManagement...

    def _ensure_file_exists(self):
        if not os.path.exists(self.file_path):
            self.save({
                'logs': '',
                'data_ultimate_connection': {'ip_ultimate_ns': '', 'ultimate_shared_key_with_ns': ''},
                'angents_data': {}
            })

    def save(self, data: SaveDataType):
        # Convert sets to lists for JSON serialization
        data_for_storage = {
            'logs': data['logs'],
            'data_ultimate_connection': data['data_ultimate_connection'],
            'angents_data': data['angents_data']
        }
        self.secure_storage.encrypt_data(data_for_storage)

    def load(self) -> SaveDataType:
        data_from_storage = self.secure_storage.decrypt_data()
        return {
            'logs': data_from_storage['logs'],
            'data_ultimate_connection': data_from_storage['data_ultimate_connection'],
            'angents_data': data_from_storage['angents_data']
        }
