from typing import Any

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
