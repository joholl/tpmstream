![GitHub Actions](https://github.com/joholl/tpmstream/actions/workflows/test.yml/badge.svg)

# tpmstream

A tool to help you understand TPM commands and responses. You can either use the
`convert` command if you want to decode TPM commands/responses or the `example`
command to find examples.

## Install

```pip install .```

For development, it is recommended to use a virtual environment and install with the `--editable` switch.

## Decode TPM Commands/Responses:

The `convert` command reads binary data from stdin:

```bash
❯ printf "80020000007700000131400000010000003d0200000000145536c0a5ba338e58abfe729f76ccca61ebaf821f01002082fc712f21e4c7e47bbf84dfa0fb15ddfc7013eb61ed3eb2edaf0286e88ba20c000400000000001a0023000b0004007200000010001a000b00000003001000000000000000000000"  | xxd -r -p | tpmstream convert
```

Or you can read from a file (can be binary or pcapng):

![Example](doc/example.png?raw=true "Example Screenshot")


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
from tpmstream.common.event import events_to_obj
from tpmstream.io.binary import Binary
from tpmstream.spec.commands.commands import Command
from tpmstream.spec.structures.constants import TPM_SU

events = Binary.marshal(tpm_type=Command, buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00")
command = events_to_obj(Command, events)

print(command.parameters.startupType)  # prints TPM_SU.CLEAR
```

Likewise, these python objects can be turned into a sequence of events, again.


```python
from tpmstream.common.event import obj_to_events

# ...

events = obj_to_events(command)

# Note that `events` is a generator. You can obtain a list by via `list(events)`
```

### Unmarshalling

Unmarshalling functions convert a given set of _MarshalEvents_ into a custom
format (binary, pretty print, ...).

```python
from tpmstream.io.binary import Binary
from tpmstream.io.pretty import Pretty
from tpmstream.spec.commands.commands import Command

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
