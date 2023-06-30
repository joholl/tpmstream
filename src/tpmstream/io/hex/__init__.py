from ...common.event import MarshalEvent
from .marshal import marshal


class Hex:
    @staticmethod
    def marshal(tpm_type, buffer, root_path=None, command_code=None, **kwargs):
        return marshal(
            tpm_type, buffer, root_path=root_path, command_code=command_code, **kwargs
        )

    @staticmethod
    def unmarshal(events: list[MarshalEvent]):
        raise NotImplementedError()
