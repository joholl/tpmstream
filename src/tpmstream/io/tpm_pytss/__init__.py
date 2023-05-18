from ...common.event import MarshalEvent
from ..binary import marshal

# from .unmarshal import unmarshal

import_error = None
try:
    from .mapping import mapping
except ImportError as error:
    import_error = error


def key_from_dict_by_value(mapping, value):
    for key, val in mapping.items():
        if val == value:
            return key
    raise KeyError()


class TpmPytss:
    @staticmethod
    def marshal(obj):
        if import_error:
            raise error
        pytss_type = type(obj)
        buffer = obj.marshal()
        try:
            tpmstream_type = key_from_dict_by_value(mapping, pytss_type)
        except KeyError:
            raise ValueError(f"Unsupported tpm-pytss type: {pytss_type}")
        yield from marshal(tpmstream_type, buffer)

    @staticmethod
    def unmarshal(events: list[MarshalEvent]):
        if import_error:
            raise error
        # TODO
        return NotImplemented
