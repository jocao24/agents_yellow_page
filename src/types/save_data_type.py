from typing_extensions import TypedDict, NotRequired


class DataUltimateConnection(TypedDict):
    ip_ultimate_ns: str
    ultimate_shared_key_with_ns: str


class SaveDataType(TypedDict):
    logs: str
    data_ultimate_connection: DataUltimateConnection
    angents_data: dict



