from ...common.event import MarshalEvent
from .unmarshal import unmarshal


class Pretty:
    @staticmethod
    def marshal(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def unmarshal(events: list[MarshalEvent]):
        return unmarshal(events)
