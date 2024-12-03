from ..binary import Binary

CMD_MARKER = b"SWTPM_IO"
CTRL_MARKER = b"Ctrl"

VALID_HEX = b"0123456789ABCDEF"
VALID_WS = b" \r\n"

STATE_WANT_CMD_MARKER = 0
STATE_WANT_CMD_START = 1
STATE_WANT_HIGH_NIBBLE = 2
STATE_WANT_LOW_NIBBLE = 3

# File format we're parsing looks like this:
#
#   Ctrl Cmd: length 4
#   00 00 00 10
#   Ctrl Rsp: length 4
#   00 00 00 00
#   SWTPM_IO_Read: length 10
#   80 01 00 00 00 0A 00 00 01 81
#   SWTPM_IO_Write: length 10
#   80 01 00 00 00 0A 00 00 01 01
#   Ctrl Cmd: length 4
#   00 00 00 01
#   Ctrl Rsp: length 8
#   00 00 00 00 00 01 FF FF
#   SWTPM_IO_Read: length 12
#   80 01 00 00 00 0C 00 00 01 44 00 00
#   SWTPM_IO_Write: length 10
#   80 01 00 00 00 0A 00 00 00 00
#   SWTPM_IO_Read: length 22
#   80 01 00 00 00 16 00 00 01 7A 00 00 00 05 00 00
#   00 00 00 00 00 01
#   SWTPM_IO_Write: length 43
#   80 01 00 00 00 2B 00 00 00 00 00 00 00 00 05 00
#   ....
#
# "Ctrl Cmd" and "Ctrl Rsp" are markers for messages
# on SWTPM's control channel, followed by data, which
# we ignore.
#
# "SWTPM_IO_Read" and "SWTPM_IO_WRITE" are markers for
# TPM commands and responses respectively, where we
# capture the following data and convert to binary.


def parse_hex_string(buffer):
    """Generator: hex string to bytes."""
    buffer = iter(buffer)

    value = bytes()
    marker = bytes()
    state = STATE_WANT_CMD_MARKER

    while True:
        try:
            b = bytes([next(buffer)])
        except StopIteration:
            b = None

        if state == STATE_WANT_CMD_MARKER:
            if b is None:
                if len(marker) != 0:
                    raise ValueError("Incomplete command marker '%s'" % str(marker))
                return
            elif b == CMD_MARKER[len(marker) : len(marker) + 1]:
                marker += b

                if marker == CMD_MARKER:
                    state = STATE_WANT_CMD_START
                    marker = bytes()
            else:
                marker = bytes()
                continue
        elif state == STATE_WANT_CMD_START:
            if b is None:
                raise ValueError("Missing command payload")
            elif b == b"\n":
                state = STATE_WANT_HIGH_NIBBLE
            else:
                continue
        elif state == STATE_WANT_HIGH_NIBBLE:
            if b is None:
                return
            elif b in VALID_WS:
                continue
            elif b == CMD_MARKER[0:1]:
                state = STATE_WANT_CMD_MARKER
                marker += b
            elif b not in VALID_HEX:
                raise ValueError("Invalid hex digit '%s'" % str(b))
            else:
                value += b
                state = STATE_WANT_LOW_NIBBLE
        elif state == STATE_WANT_LOW_NIBBLE:
            if b is None:
                raise ValueError("Incomplete command byte")
            elif value == CTRL_MARKER[0:1] and b == CTRL_MARKER[1:2]:
                state = STATE_WANT_CMD_MARKER
                value = bytes()
            elif b not in VALID_HEX:
                raise ValueError("Invalid hex digit '%s'" % str(b))
            else:
                value += b
                i = int(value, 16)
                value = bytes()
                state = STATE_WANT_HIGH_NIBBLE
                yield i


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
