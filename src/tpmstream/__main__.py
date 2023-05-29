import binascii
import sys
from argparse import ArgumentParser, FileType
from dataclasses import fields
from difflib import get_close_matches

from . import __version__
from .common.object import events_to_objs, obj_to_events
from .data import example_data_files
from .io import bytes_from_files
from .io.auto import Auto
from .io.binary import Binary
from .io.events import Events
from .io.pcapng import Pcapng
from .io.pretty import Pretty
from .spec import all_types
from .spec.commands import CommandResponseStream, Response

# TODO import .io.tpm_pytss.mapping
from .spec.structures.constants import TPM_CC

parser = ArgumentParser(
    description="Process TPM 2.0 commands and responses.",
)


def cc_name(command_code: TPM_CC):
    # strip leading "TPM_CC."
    return str(command_code)[len(TPM_CC.__name__) + 1 :]


def fuzzy_match(input: str, options: dict[str, any], name=None):
    if name is None:
        name = "value"

    try:
        result = options[input]
    except KeyError:
        pass
    else:
        return result

    # failed to match, propose closest fit
    closest_match = get_close_matches(input, options.keys(), n=1, cutoff=0)[0]
    # TODO this can replace other parts of the command
    proposal = f"{parser.prog} {' '.join(sys.argv[1:]).replace(input, closest_match)}"
    print(
        f"Unknown {name}: {input}.\n\nDid you mean:\n\n  {proposal}\n",
        file=sys.stderr,
    )
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

    command_code = None
    if args.type is None:
        tpm_type = CommandResponseStream
    else:
        tpm_type = fuzzy_match(args.type, {t.__name__: t for t in all_types}, "type")
        if tpm_type is None:
            return -1
        if tpm_type is Response:
            if not args.command:
                print(
                    f"Error: --type=Response requires --command=<command>.",
                    file=sys.stderr,
                )
                return -1
            command_code = fuzzy_match(
                args.command, {cc_name(cc): cc for cc in TPM_CC}, name="commandCode"
            )
            if command_code is None:
                return -1

    if tpm_type is not CommandResponseStream and args.format_in == "auto":
        raise RuntimeError(
            "Custom type (--type=...) is incompatible with --in=auto (default). Did you mean --in=binary?"
        )

    # binary to events to pretty
    # TODO abort_on_error as cli argument
    events = format_in.marshal(
        tpm_type=tpm_type,
        buffer=bytes_from_files(args.file),
        command_code=command_code,
        abort_on_error=False,
    )

    for line in format_out.unmarshal(events):
        if isinstance(line, bytes):
            print(" " + binascii.hexlify(line).decode(), end="")
        else:
            print(line)

    return 0


def find_fields(tpm_type, obj: any):
    if type(obj) is tpm_type:
        yield obj
    try:
        obj_fields = fields(obj)
    except TypeError:
        return

    for field in obj_fields:
        yield from find_fields(tpm_type=tpm_type, obj=getattr(obj, field.name))


def examples(args):
    if args.command is None:
        for command_code in TPM_CC:
            # remove leading "TPM_CC_"
            print(cc_name(command_code))
        return

    command_codes = {cc_name(cc): cc for cc in TPM_CC}
    # TODO what about Command, Response and CommandResponseStream?
    types = {t.__name__: t for t in all_types}
    assert len(set(command_codes.keys()) & set(types.keys())) == 0

    types_and_command_codes = {cc_name(cc): cc for cc in TPM_CC} | {
        t.__name__: t for t in all_types
    }
    sought_type_or_command_code = fuzzy_match(
        args.command, types_and_command_codes, name="command or type"
    )
    if sought_type_or_command_code is None:
        return -1

    if sought_type_or_command_code in types.values():
        command_code = None
        tpm_type = sought_type_or_command_code
    else:
        command_code = sought_type_or_command_code
        tpm_type = None

    already_printed: set[bytes] = set()
    for example_data_file in example_data_files:
        with open(example_data_file, "rb") as file:
            bytes_from_file = bytes(bytes_from_files(file))
            events = Auto.marshal(
                tpm_type=CommandResponseStream,
                buffer=bytes_from_file,
                abort_on_error=False,
            )

        for obj in events_to_objs(events):
            if (
                command_code is None
                or (  # command
                    hasattr(obj, "commandCode") and obj.commandCode == command_code
                )
                or (  # response
                    hasattr(obj, "_command_code") and obj._command_code == command_code
                )
            ):
                if tpm_type:
                    objs_to_print = list(find_fields(tpm_type=tpm_type, obj=obj))
                else:
                    objs_to_print = (obj,)

                for obj_to_print in objs_to_print:
                    events = list(obj_to_events(obj_to_print))
                    binary_list = list(Binary.unmarshal(events))
                    binary = b"".join(binary_list)

                    if binary in already_printed:
                        continue

                    print(f"{type(obj_to_print).__name__}:", end="")
                    for binary_part in binary_list:
                        print(" " + binascii.hexlify(binary_part).decode(), end="")
                    print()
                    for line in Pretty.unmarshal(events):
                        print(line)
                    print()

                    already_printed.add(binary)

    return 0


parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
subparsers = parser.add_subparsers()
subparsers.required = True

format_in_arg = {
    "dest": "format_in",
    "type": str,
    "choices": ["binary", "pcapng", "auto"],
    "default": "auto",
    "help": "input stream format, default is auto (--in=auto only works with --type=CommandResponseStream)",
}
format_out_arg = {
    "dest": "format_out",
    "type": str,
    "choices": ["binary", "events", "pretty"],
    "default": "pretty",
    "help": "output stream format, default is pretty",
}
type_arg = {
    "dest": "type",
    "type": str,
    "help": "type to parse, default is CommandResponseStream",
}
command_arg = {
    "dest": "command",
    "type": str,
    "help": "For --type=Response: command this response corresponds to, e.g. GetRandom",
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
parser_convert.add_argument("--type", **type_arg)
parser_convert.add_argument("--command", **command_arg)
parser_convert.set_defaults(func=convert)

parser_example = subparsers.add_parser("example", aliases=["ex"])
parser_example.add_argument(
    "command", type=str, nargs="?", help="TPM Command, like GetRandom"
)
# TODO add type_arg
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
