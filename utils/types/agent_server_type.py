from typing_extensions import TypedDict, NotRequired, Any


class AgentServerType(TypedDict):
    id: str
    name: str
    description: str
    ip_agent: str
    skills: list[str]
