from functools import cached_property

from tpmstream.common.object import obj_to_events
from tpmstream.io.auto import Auto
from tpmstream.io.pretty import Pretty
from tpmstream.spec.commands import command_response_types
from tpmstream.spec.structures import structures_types


class Generator:
    """Class for getting the return value of a generator."""

    def __init__(self, gen):
        self.gen = gen

    def __iter__(self):
        self.value = yield from self.gen


class Canonical:
    def __init__(
        self,
        input,
        format_in=Auto,
        tpm_type=None,
        path=None,
        command_code=None,
        lazy=True,
        abort_on_error=True,
    ):
        if any(isinstance(input, t) for t in structures_types + command_response_types):
            # input is an object of a tpm_type
            self._object = input
            self._events = Generator(obj_to_events(input, path=path))
        elif isinstance(input, bytes):
            # input is bytes buffer
            self._object = None
            self._events = Generator(
                format_in.marshal(
                    tpm_type=tpm_type,
                    buffer=input,
                    root_path=path,
                    command_code=command_code,
                    abort_on_error=abort_on_error,
                )
            )
        # elif hasattr(input, "__iter__"):
        #     # input is iterable
        #     events = Generator(iter(input))
        else:
            raise ValueError(f"Unknown input type: {input}")

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
        if isinstance(self._events, Generator):
            events_list = list(self._events)
            if self._object is None:
                self._object = self._events.value
            self._events = events_list
        return self._events

    def __iter__(self):
        return self.events

    @cached_property
    def object(self):
        if self._object is None:
            self.events  # resolve
            assert self._object is not None
        return self._object
