[![CI](https://github.com/joholl/tpmstream/actions/workflows/test.yml/badge.svg)](https://github.com/joholl/tpmstream/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/tpmstream)](https://pypi.org/project/tpmstream)

# tpmstream

A tool to help you understand TPM commands and responses. You can either use the
`convert` command if you want to decode TPM commands/responses or the `example`
command to find examples.

Try it online at [joholl.github.io/tpmstream-web](https://joholl.github.io/tpmstream-web)!

## Install

```pip install .```

For development, it is recommended to use a virtual environment and install with the `--editable` switch.

## Decode TPM Commands/Responses:

The `convert` command reads binary (or pcapng) data from a file:

```bash
❯ tpmstream convert create_primary.bin
```

![Example](doc/example.png?raw=true "Example Screenshot")


Or you can read data from stdin. Just pass `-`:

```bash
❯ printf "80020000007700000131400000010000003d0200000000145536c0a5ba338e58abfe729f76ccca61ebaf821f01002082fc712f21e4c7e47bbf84dfa0fb15ddfc7013eb61ed3eb2edaf0286e88ba20c000400000000001a0023000b0004007200000010001a000b00000003001000000000000000000000"  | xxd -r -p | tpmstream convert -
```

## Find Examples for TPM Commands/Responses:

You want to see an exemplary TPM command? Easy, try:
```bash
❯ tpmstream ex NV_Write
```

Don't worry, the tool helps you out if you do not know how to spell a given command:

```bash
❯ tpmstream ex NVDefine
Unknown commandCode: NVDefine.

Did you mean:

  tpmstream ex NV_DefineSpace
```


## Python API

### Marshalling

Marshalling functions convert a particular data stream (binary, pcapng, ...)
into a canonical format: a sequence of _MarshalEvents_. These events can be
converted to a python representation of the respective datatype (e.g. a
`TPMS_SIG_SCHEME_ECDSA` object).

```python
from tpmstream.common.object import events_to_obj
from tpmstream.io.binary import Binary
from tpmstream.spec.commands import Command
from tpmstream.spec.structures.constants import TPM_SU

events = Binary.marshal(tpm_type=Command, buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00")
command = events_to_obj(events)

print(command.parameters.startupType)  # prints TPM_SU.CLEAR
```

Likewise, these python objects can be turned into a sequence of events, again.


```python
from tpmstream.common.object import obj_to_events
from tpmstream.io.binary import Binary
from tpmstream.spec.commands import Command
from tpmstream.spec.commands.commands_handles import TPMS_COMMAND_HANDLES_STARTUP
from tpmstream.spec.commands.commands_params import TPMS_COMMAND_PARAMS_STARTUP
from tpmstream.spec.structures.base_types import UINT32
from tpmstream.spec.structures.constants import TPM_CC, TPM_ST, TPM_SU
from tpmstream.spec.structures.interface_types import TPMI_ST_COMMAND_TAG

startup_command = Command(
     tag=TPMI_ST_COMMAND_TAG(TPM_ST.NO_SESSIONS),
     commandSize=UINT32(12),
     commandCode=TPM_CC.Startup,
     handles=TPMS_COMMAND_HANDLES_STARTUP(),
     parameters=TPMS_COMMAND_PARAMS_STARTUP(startupType=TPM_SU.CLEAR),
)

events = obj_to_events(startup_command)

# Note that `events` is a generator. You can obtain a list by via `list(events)`
```

### Unmarshalling

Unmarshalling functions convert a given set of _MarshalEvents_ into a custom
format (binary, pretty print, ...).

```python
from tpmstream.io.binary import Binary
from tpmstream.io.pretty import Pretty
from tpmstream.spec.commands import Command

events = Binary.marshal(tpm_type=Command, buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00")
pretty = Pretty.unmarshal(events=events)

for line in pretty:
     print(line)
```


### Example flow

Marshalling (e.g. binary to events) and unmarshalling (e.g. events to pretty
print) is decoupled. Events can be turnt into python objects (like
`TPMS_SIG_SCHEME_ECDSA`) and vice versa.

```
               +---------------------+                                                         +----------------------+
---[binary]--> | binary marshalling  | ---[events]---+-------------------------+---[events]--> | binary unmarshalling | ---[pretty print]-->
               +---------------------+               |                         |               +----------------------+
                                                     |    +---------------+    |
                                                     +--> | python object | ---+
                                                          +---------------+
```
