from ..common.values import tpm_dataclass, tpm_enum
from .base_types import UINT32


@tpm_enum
class TPM_AT(UINT32):
    ANY = 0x00000000
    ERROR = 0x00000001
    PV1 = 0x00000002
    VEND = 0x80000000


@tpm_enum
class TPM_AE(UINT32):
    TPM_AE_NONE = 0x00000000


@tpm_dataclass
class TPMS_AC_OUTPUT:
    tag: TPM_AT
    data: UINT32


@tpm_dataclass
class TPML_AC_CAPABILITIES:
    count: UINT32
    acCapabilities: list[TPMS_AC_OUTPUT]
