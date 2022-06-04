import binascii
import glob
import os
import sys
from argparse import ArgumentParser, FileType
from difflib import get_close_matches

from tpmstream.common.event import events_to_objs, obj_to_events
from tpmstream.spec.structures.constants import TPM_CC

from . import __version__
from .io import bytes_from_files
from .io.auto import Auto
from .io.binary import Binary
from .io.events import Events
from .io.pcapng import Pcapng
from .io.pretty import Pretty
from .spec.commands.commands import Command

parser = ArgumentParser(
    description="Process TPM 2.0 commands and responses.",
)


def get_command_code(input):
    """Return TPM_CC if represented by input, or None otherwise."""
    for command_code in TPM_CC:
        # strip the leading "TPM_CC." and then compare with some variations
        base = f"{command_code}"[len(TPM_CC.__name__) + 1 :]
        valid_variations = (
            f"{base}",  # NV_Write
            f"TPM2_{base}",  # TPM2_NV_Write
            f"TPM_CC_{base}",  # TPM_CC_NV_Write
            f"TPM_CC.{base}",  # TPM_CC.NV_Write
        )

        if input in valid_variations:
            return command_code

    return None


def convert(args):
    format_in = {
        "auto": Auto,
        "binary": Binary,
        "pcapng": Pcapng,
    }[args.format_in]

    format_out = {
        "binary": Binary,
        "events": Events,
        "pretty": Pretty,
    }[args.format_out]

    # binary to events to pretty
    events = format_in.marshal(tpm_type=Command, buffer=bytes_from_files(args.file))
    for line in format_out.unmarshal(events):
        if isinstance(line, bytes):
            print(" " + binascii.hexlify(line).decode(), end="")
        else:
            print(line)

    return 0


def examples(args):
    # TODO we can do better
    TPMSTREAM_PATH = os.path.abspath(os.path.dirname(__file__))
    PCAP_DIRECORY_PATH = os.path.join(
        os.path.dirname(os.path.dirname(TPMSTREAM_PATH)), "test/pcap/*.pcap"
    )
    paths = sorted(glob.glob(PCAP_DIRECORY_PATH))

    if args.command is None:
        for command_code in TPM_CC:
            # remove leading "TPM_CC_"
            print(str(command_code)[len(TPM_CC.__name__) + 1 :])
        return

    sought_command_code = get_command_code(args.command)
    if sought_command_code is None:
        # failed to match command_code, propose closest fit
        options = [
            str(command_code)[len(TPM_CC.__name__) + 1 :] for command_code in TPM_CC
        ]
        closest_match = get_close_matches(args.command, options, n=1, cutoff=0)[0]
        proposal = f"{parser.prog} {''.join(sys.argv[1:-1])} {closest_match}"
        print(
            f"Unknown commandCode: {args.command}.\n\nDid you mean:\n\n  {proposal}\n",
            file=sys.stderr,
        )
        return -1

    try:
        sought_command_code = getattr(TPM_CC, args.command)
    except AttributeError as e:
        raise AttributeError(f"Unknown commandCode: {args.command}") from e

    for path in paths:
        with open(path, "rb") as file:
            events = list(Auto.marshal(tpm_type=Command, buffer=bytes_from_files(file)))

        # TODO Get Responses, too. Response objects should know they commandCode, maybe via ._commandCode?
        for cmd_or_rsp in events_to_objs(events):
            if (
                hasattr(cmd_or_rsp, "commandCode")
                and cmd_or_rsp.commandCode == sought_command_code
            ):
                events_from_obj = list(obj_to_events(cmd_or_rsp))
                for item in Binary.unmarshal(events_from_obj):
                    print(" " + binascii.hexlify(item).decode(), end="")
                print()
                for line in Pretty.unmarshal(events_from_obj):
                    print(line)
                print()

    return 0


parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
subparsers = parser.add_subparsers()
subparsers.required = True

format_in_arg = {
    "dest": "format_in",
    "type": str,
    "choices": ["binary", "pcapng", "auto"],
    "default": "auto",
    "help": "input stream format",
}
format_out_arg = {
    "dest": "format_out",
    "type": str,
    "choices": ["binary", "events", "pretty"],
    "default": "pretty",
    "help": "output stream format",
}

parser_convert = subparsers.add_parser(
    "convert",
    aliases=["co"],
    description="convert data stream to another format",
)
parser_convert.add_argument(
    "file", type=FileType("rb"), nargs="+", help="input file(s) to be parsed"
)
parser_convert.add_argument("--in", **format_in_arg)
parser_convert.add_argument("--out", **format_out_arg)
parser_convert.set_defaults(func=convert)

parser_example = subparsers.add_parser("example", aliases=["ex"])
parser_example.add_argument(
    "command", type=str, nargs="?", help="TPM Command, like TPM2_GetRandom"
)
parser_example.set_defaults(func=examples)

# TODO requires eval "$(register-python-argcomplete tpmstream/__main__.py)"
# TODO what about subparsers?
# argcomplete(parser)


def main(argv=None):
    args = parser.parse_args()
    ret = args.func(args)
    sys.exit(ret)


if __name__ == "__main__":
    main()
