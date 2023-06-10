import inspect
from typing import Any, Union

from tpmstream.spec.commands import (
    commands_handles,
    commands_params,
    responses_handles,
    responses_params,
)
from tpmstream.spec.commands.responses_handles import response_handle_types
from tpmstream.spec.commands.responses_params import response_param_types
from tpmstream.spec.common.values import tpm_dataclass
from tpmstream.spec.structures.base_types import UINT32
from tpmstream.spec.structures.constants import TPM_RC, TPM_ST
from tpmstream.spec.structures.structures import TPMS_AUTH_RESPONSE

from ..common.values import tpm_dataclass
from ..structures.base_types import UINT32
from ..structures.constants import TPM_CC
from ..structures.interface_types import TPMI_ST_COMMAND_TAG
from ..structures.structures import TPMS_AUTH_COMMAND
from .commands_handles import command_handle_types
from .commands_params import command_param_types

# TODO plus-type handle and param member types


@tpm_dataclass
class Command:
    _selectors = {
        "handles": "commandCode",
        "parameters": "commandCode",
    }
    _type_maps = {
        "handles": command_handle_types,
        "parameters": command_param_types,
    }

    tag: TPMI_ST_COMMAND_TAG
    commandSize: UINT32
    commandCode: TPM_CC
    handles: Any
    # authSize and authorizationArea are not present if tag indicates no session
    authSize: UINT32
    authorizationArea: list[TPMS_AUTH_COMMAND]
    parameters: Any


# ensure that every TPM_CC maps to command handles/parameters
assert all(cc in command_handle_types for cc in TPM_CC)
assert all(cc in command_param_types for cc in TPM_CC)


@tpm_dataclass
class Response:
    # _selectors: selector is always commandCode from the Command
    _type_maps = {
        "handles": response_handle_types,
        "parameters": response_param_types,
    }
    # _command_code: added when object is created

    tag: TPM_ST
    responseSize: UINT32
    responseCode: TPM_RC
    # handles, parameterSize, parameters and authorizationArea are not present if responseCode is fail
    handles: Any
    parameterSize: UINT32
    parameters: Any
    authorizationArea: list[TPMS_AUTH_RESPONSE]


# ensure that every TPM_CC (sic!) maps to response handles/parameters
assert all(cc in response_handle_types for cc in TPM_CC)
assert all(cc in response_param_types for cc in TPM_CC)


class CommandResponseStream(list[Union[Command, Response]]):
    pass


submodules = (
    commands_handles,
    commands_params,
    responses_handles,
    responses_params,
)

# provide all specified types in a single list
command_response_types_set = {Command, Response, CommandResponseStream}
for module in submodules:
    command_response_types_set.update(
        obj
        for name, obj in inspect.getmembers(module, inspect.isclass)
        if (
            obj.__name__.startswith("TPMS_COMMAND_HANDLES")
            or obj.__name__.startswith("TPMS_RESPONSE_HANDLES")
            or obj.__name__.startswith("TPMS_COMMAND_PARAMS")
            or obj.__name__.startswith("TPMS_RESPONSE_PARAMS")
        )
    )
command_response_types = sorted(command_response_types_set, key=lambda e: e.__name__)
