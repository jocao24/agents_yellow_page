from typing_extensions import TypedDict, NotRequired


class ClientServerType(TypedDict):
    id: str
    name: str
    description: str
    ip_client: str
