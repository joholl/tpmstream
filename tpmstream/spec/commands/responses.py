from typing import Any

from tpmstream.spec.commands.responses_handles import response_handle_types
from tpmstream.spec.commands.responses_params import response_param_types
from tpmstream.spec.common.values import tpm_dataclass
from tpmstream.spec.structures.base_types import UINT32
from tpmstream.spec.structures.constants import TPM_RC, TPM_ST
from tpmstream.spec.structures.structures import TPMS_AUTH_RESPONSE


@tpm_dataclass
class Response:
    # _selectors: selector is always commandCode from the Command
    _type_maps = {
        "handles": response_handle_types,
        "parameters": response_param_types,
    }

    tag: TPM_ST
    responseSize: UINT32
    responseCode: TPM_RC
    handles: Any
    # parameterSize, parameters and authorizationArea are not present if responseCode is fail
    parameterSize: UINT32
    parameters: Any
    authorizationArea: list[TPMS_AUTH_RESPONSE]
