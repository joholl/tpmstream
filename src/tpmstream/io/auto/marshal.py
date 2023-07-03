import binascii
import re

from ..binary import Binary
from ..hex import Hex
from ..pcapng import Pcapng


def detect_format_and_yield_buffer(buffer, strict=True):
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
        yield "pcapng"
    else:
        if re.match(b"[0-9a-fA-F]{2}", look_ahead):
            # look ahead is valid hex, so it's MAYBE hex
            if not strict:
                yield "hex"
            else:
                raise IOError(
                    f"Ambiguous input format: magic number is {binascii.hexlify(look_ahead).decode()}. Could be binary or hex."
                )
        else:
            # not valid hex, so it must be binary
            yield "binary"

    yield from look_ahead
    yield from buffer_iter


def marshal(
    tpm_type, buffer, root_path=None, command_code=None, strict=False, **kwargs
):
    """Generator. Take iterable which yields single bytes. Yield MarshalEvents. Be smart about format."""
    format_buffer_iter = detect_format_and_yield_buffer(buffer, strict=strict)

    format = next(format_buffer_iter)

    if format == "pcapng":
        result = yield from Pcapng.marshal(
            tpm_type=tpm_type,
            buffer=format_buffer_iter,
            root_path=root_path,
            command_code=command_code,
            **kwargs,
        )
        return result
    if format == "hex":
        result = yield from Hex.marshal(
            tpm_type=tpm_type,
            buffer=format_buffer_iter,
            root_path=root_path,
            command_code=command_code,
            **kwargs,
        )
        return result
    if format == "binary":
        result = yield from Binary.marshal(
            tpm_type=tpm_type,
            buffer=format_buffer_iter,
            root_path=root_path,
            command_code=command_code,
            **kwargs,
        )
        return result
    raise RuntimeError(f"Unknown input format: {format}")
