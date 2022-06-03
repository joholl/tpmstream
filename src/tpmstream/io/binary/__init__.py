from ...common.event import MarshalEvent
from .marshal import marshal_all
from .unmarshal import unmarshal


class Binary:
    @staticmethod
    def marshal(tpm_type, buffer, root_path=None, command_code=None):
        return marshal_all(
            tpm_type, buffer, root_path=root_path, command_code=command_code
        )

    @staticmethod
    def unmarshal(events: list[MarshalEvent]):
        return unmarshal(events)
