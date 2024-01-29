import_error = None
try:
    from tpm2_pytss import TCTILdr
except ImportError as error:
    import_error = error

from tpmstream.io.binary import Binary
from tpmstream.io.pretty import Pretty
from tpmstream.spec.commands import Command, Response


# To use tpmstream with tcti-py, we define a tcti
# see https://github.com/tpm2-software/tpm2-tss/pull/2749
class TpmstreamTCTI(object):
    def __init__(self, args: str | None):
        def parse_args(args: str | None):
            if args is None:
                return {"name": None, "conf": None}
            if ":" not in args:
                return {"name": args, "conf": None}

            name, conf = args.split(":", maxsplit=1)
            return {"name": name, "conf": conf}

        nameconf = parse_args(args)
        print(f"PYTHON: Initializing TCTI Ldr with mod: {nameconf}")
        self._tcti = TCTILdr(**nameconf)
        self._command_code = None

    @property
    def magic(self):
        return 0x74706D7374726561

    def receive(self, timeout: int) -> bytes:
        result = self._tcti.receive(timeout=timeout)

        events = Binary.marshal(
            tpm_type=Response,
            buffer=result,
            command_code=self._command_code,
            abort_on_error=False,
        )
        for line in Pretty.unmarshal(events):
            if isinstance(line, bytes):
                print(" " + binascii.hexlify(line).decode(), end="")
            else:
                print(line)

        return result

    def transmit(self, buffer: bytes):
        events = Binary.marshal(
            tpm_type=Command,
            buffer=buffer,
            abort_on_error=False,
        )
        for line in Pretty.unmarshal(events):
            if isinstance(line, bytes):
                print(" " + binascii.hexlify(line).decode(), end="")
            else:
                print(line)
        self._command_code = int.from_bytes(buffer[6:10], byteorder="big")

        self._tcti.transmit(buffer)


def tcti_init(args: str) -> TpmstreamTCTI:
    if import_error:
        raise import_error
    return TpmstreamTCTI(args)
