import binascii

from ...spec.structures.interface_types import TPMI_ST_COMMAND_TAG
from ..binary import Binary
from ..pcapng import Pcapng


def detect_format_and_yield_buffer(buffer):
    """First yield is format. Rest is buffer bytewise."""
    buffer_iter = iter(buffer)

    look_ahead = b""
    try:
        look_ahead += bytes((next(buffer_iter), next(buffer_iter)))
    except StopIteration as e:
        raise IOError(
            f"Unknown detect input format: {binascii.hexlify(buffer).decode()}"
        ) from e

    if look_ahead == b"\x0a\x0d":
        # TODO use enum or some sort of canonical mapping?
        yield "pcapng"
    elif look_ahead in (
        tag.to_bytes() for tag in TPMI_ST_COMMAND_TAG._valid_values._values
    ):
        yield "binary"
    else:
        raise IOError(
            f"Unknown detect input format: {binascii.hexlify(buffer).decode()}"
        )

    yield from look_ahead
    yield from buffer_iter


def marshal(tpm_type, buffer, root_path=None, command_code=None):
    """Generator. Take iterable which yields single bytes. Yield MarshalEvents. Be smart about format."""
    format_buffer_iter = detect_format_and_yield_buffer(buffer)

    format = next(format_buffer_iter)

    if format == "pcapng":
        yield from Pcapng.marshal(
            tpm_type,
            buffer=format_buffer_iter,
            root_path=root_path,
            command_code=command_code,
        )
    elif format == "binary":
        yield from Binary.marshal(
            tpm_type,
            buffer=format_buffer_iter,
            root_path=root_path,
            command_code=command_code,
        )
    else:
        raise RuntimeError(f"Unknown input format: {format}")
