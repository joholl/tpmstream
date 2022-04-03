from ...common.event import MarshalEvent
from .unmarshal import unmarshal


class Events:
    @staticmethod
    def marshal(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def unmarshal(events: list[MarshalEvent]):
        return unmarshal(events)
