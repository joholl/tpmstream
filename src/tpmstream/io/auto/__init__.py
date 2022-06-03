from ...common.event import MarshalEvent
from .marshal import marshal


class Auto:
    @staticmethod
    def marshal(tpm_type, buffer, root_path=None, command_code=None):
        return marshal(tpm_type, buffer, root_path=root_path, command_code=command_code)

    @staticmethod
    def unmarshal(events: list[MarshalEvent]):
        raise NotImplementedError()
