from ...common.event import MarshalEvent
from .marshal import marshal
from .unmarshal import unmarshal


class Binary:
    @staticmethod
    def marshal(**kwargs):
        return marshal(**kwargs)

    @staticmethod
    def unmarshal(events: list[MarshalEvent]):
        return unmarshal(events)
