from functools import cached_property
from types import GeneratorType

from tpmstream.common.object import events_to_obj, obj_to_events
from tpmstream.io.auto import Auto
from tpmstream.io.pretty import Pretty
from tpmstream.spec.commands import command_response_types
from tpmstream.spec.structures import structures_types


class Canonical:
    def __init__(
        self,
        input,
        tpm_type=None,
        path=None,
        command_code=None,
        lazy=True,
        abort_on_error=True,
    ):
        if any(isinstance(input, t) for t in structures_types + command_response_types):
            events = obj_to_events(input, path=path)
        elif isinstance(input, bytes):
            events = Auto.marshal(
                tpm_type=tpm_type,
                buffer=input,
                root_path=path,
                command_code=command_code,
                abort_on_error=abort_on_error,
            )
        elif hasattr(input, "__iter__"):
            events = iter(input)
        else:
            raise ValueError(f"Unknown input type: {input}")

        self._events = events
        if not lazy:
            self.events  # resolve

    def debug(self):
        try:
            for line in Pretty.unmarshal(self._events):
                print(line)
        except Exception as error:
            print(__import__("traceback").format_exc())

    @cached_property
    def events(self):
        if isinstance(self._events, GeneratorType):
            self._events = list(self._events)
        return self._events

    def __iter__(self):
        return self.events

    @cached_property
    def object(self):
        return events_to_obj(self.events)
