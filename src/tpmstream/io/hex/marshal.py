from ..binary import Binary


def parse_hex_string(buffer):
    """Generator: hex string to bytes."""
    buffer = iter(buffer)

    high_nibble = b""
    low_nibble = b""

    while True:
        # first fill high_nibble until non-whitespace
        try:
            if not high_nibble.strip():
                high_nibble = bytes([next(buffer)])
                continue
        except StopIteration:
            return

        # then fill low_nibble until non-whitespace
        try:
            if not low_nibble.strip():
                low_nibble = bytes([next(buffer)])
                continue
        except StopIteration:
            raise ValueError("Invalid hex string: uneven amount of digits.")

        # parse
        yield int(high_nibble + low_nibble, 16)

        high_nibble = b""
        low_nibble = b""


def marshal(tpm_type, buffer, root_path=None, command_code=None, **kwargs):
    """Generator. Take iterable which yields single bytes. Yield MarshalEvents."""
    parsed_bytes = parse_hex_string(buffer)

    result = yield from Binary.marshal(
        tpm_type=tpm_type,
        buffer=parsed_bytes,
        root_path=root_path,
        command_code=command_code,
        **kwargs,
    )
    return result
