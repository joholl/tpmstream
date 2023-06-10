import binascii

from tpmstream.common.event import Event, InfoEvent, MarshalEvent
from tpmstream.common.util import is_list
from tpmstream.spec.structures.base_types import BYTE

from ...common.path import PathNode
from ..binary.unmarshal import unmarshal as binary_unmarshal

try:
    from colorama import init
    from colorama.ansi import Fore, Style
except ModuleNotFoundError:
    # mock for brython
    class Fore:
        def __getattr__(self, _name):
            return ""

    class Style:
        def __getattr__(self, _name):
            return ""

else:
    init()


# TODO to args
show_attributes = True


def unmarshal(events: list[Event]):
    """Generator. Take iterable which yields MarshalEvent. Yield strings."""
    # TODO do not print list parents (unless list is empty)
    events = iter(events)

    for event in events:
        if (
            isinstance(event, MarshalEvent)
            and is_list(event.type)
            and event.value is ...
        ):
            # this is a list parent
            event = yield from pretty_list_elems(event, events)
            if event is None:
                return

        yield from pretty(event)
        if (
            show_attributes
            and isinstance(event, MarshalEvent)
            and hasattr(event.value, "attributes")
        ):
            yield from pretty_attrs(event)


def get_type_name(tpm_type):
    if tpm_type is None:
        return ""
    if is_list(tpm_type):
        assert len(tpm_type.__args__) == 1
        return f"{tpm_type.__name__}[{tpm_type.__args__[0].__name__}]"
    else:
        return tpm_type.__name__


def format(tpm_type, path, binary, value):
    # TODO take a format string (given via args)
    # TODO less padding (autodetermine)
    layer = len(path) - 1
    indent = f"{Fore.BLACK}{'|   ' * layer}{Style.RESET_ALL}"
    type_name = f"{Fore.BLUE}{get_type_name(tpm_type)}{Style.RESET_ALL}"
    name = f"{indent}{Fore.LIGHTGREEN_EX}.{path[-1]}{Style.RESET_ALL}"
    result = f"{type_name: <50} {name: <64}"
    if binary:
        binary = binascii.hexlify(binary).decode()
    else:
        binary = ""
    binary = f"{Fore.YELLOW}{binary: <20}{Style.RESET_ALL}"
    result = f"{result} {binary}"
    value = "" if value is ... else f"{Fore.YELLOW}{value}{Style.RESET_ALL}"
    result = f"{result} {value}"
    return result


def format_info(event: InfoEvent):
    return f"{Fore.RED}{event}{Style.RESET_ALL}"


def pretty(event: Event):
    """Generate human-readable string from field."""
    if not isinstance(event, MarshalEvent):
        yield format_info(event)
        return

    if event.value is ...:
        value = ""
    else:
        value = f"{event.value}"

    data = b"".join(binary_unmarshal((event,)))

    yield format(event.type, event.path, data, value)


def pretty_list_elems(parent_event: MarshalEvent, events_generator):
    """Generate human-readable string from list fields. Consumes from events_generator. Returns next non-list item or None."""
    assert len(parent_event.type.__args__) == 1
    # TODO there are non-tpm2b list[BYTE]s... get as param?
    is_tpm2b = is_list(parent_event.type) and parent_event.type.__args__[0] is BYTE
    is_empty = True

    def is_child(parent: MarshalEvent, event: MarshalEvent):
        return (
            parent.path[:-1] == event.path[:-1]
            and parent.path[-1].name == event.path[-1].name
        )

    if is_tpm2b:
        # consume all list elements
        child_buffer = b""
        while True:
            # get next (potential) child_event
            try:
                child_event = next(events_generator)
            except StopIteration:
                child_event = None
                break

            if not isinstance(child_event, MarshalEvent):
                yield from pretty(child_event)
                continue

            # abort if it is not a list element
            if not is_child(parent_event, child_event):
                break

            child_buffer += child_event.value.to_bytes()

        filter = b"................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."
        printable = child_buffer.translate(filter).decode()
        yield format(parent_event.type, parent_event.path, child_buffer, printable)
        return child_event
    else:
        # consume all list elements
        while True:
            # get next (potential) child_event
            try:
                child_event = next(events_generator)
            except StopIteration:
                if is_empty:
                    yield from pretty(parent_event)
                return None

            if not isinstance(child_event, MarshalEvent):
                yield from pretty(child_event)
                continue

            # abort if it is not a list element
            if not is_child(parent_event, child_event):
                if is_empty:
                    yield from pretty(parent_event)
                return child_event

            yield from pretty(child_event)
            is_empty = False


def pretty_attrs(event: MarshalEvent):
    """Generate human-readable string from attributes field."""
    if not hasattr(event.value, "attributes"):
        return

    # for attr_bits, attr_name in event.value.attributes():
    #     if isinstance(attr_bits, int):
    #         mask = 1 << attr_bits
    #     else:
    #         mask = 0
    #         attr_bit_min, attr_bit_max = attr_bits
    #         for attr_bit in range(attr_bit_min, attr_bit_max + 1):
    #             mask |= 1 << attr_bit
    #
    #     size = event.value._int_size
    #     path = event.path + PathNode(attr_name)
    #
    #     bit_size = size * 8
    #     mask_padded = f"{mask:b}".zfill(bit_size)
    #     value_padded = f"{event.value:b}".zfill(bit_size)
    #     bits = "".join(
    #         "." if m == "0" else v
    #         for m, v
    #         in zip(mask_padded, value_padded)
    #     )
    #
    #     yield format(None, path, None, bits)

    for attribute in event.value.attributes():
        mask = attribute._value

        size = event.value._int_size
        path = event.path + PathNode(attribute._name)

        bit_size = size * 8
        mask_padded = f"{mask:b}".zfill(bit_size)
        value_padded = f"{event.value._value:b}".zfill(bit_size)
        bits = "".join(
            "." if m == "0" else v for m, v in zip(mask_padded, value_padded)
        )
        if attribute._details:
            bits = f"{bits}  {attribute._details}"

        yield format(None, path, None, bits)
