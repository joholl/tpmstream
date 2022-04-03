from ..common.values import ValidValues, tpm_enum
from .base_types import UINT8, UINT32


@tpm_enum
class TPM_HT(UINT8):
    PCR = 0x00
    NV_INDEX = 0x01
    HMAC_SESSION = 0x02
    LOADED_SESSION = 0x02
    POLICY_SESSION = 0x03
    SAVED_SESSION = 0x03
    PERMANENT = 0x40
    TRANSIENT = 0x80
    PERSISTENT = 0x81
    AC = 0x90


@tpm_enum
class TPM_RH(UINT32):
    """Permanent Handles."""

    SRK = 0x40000000
    OWNER = 0x40000001
    REVOKE = 0x40000002
    TRANSPORT = 0x40000003
    OPERATOR = 0x40000004
    ADMIN = 0x40000005
    EK = 0x40000006
    NULL = 0x40000007
    UNASSIGNED = 0x40000008
    LOCKOUT = 0x4000000A
    ENDORSEMENT = 0x4000000B
    PLATFORM = 0x4000000C
    PLATFORM_NV = 0x4000000D
    AUTH = range(0x40000010, 0x40000110)
    ACT = range(0x40000110, 0x40000120)


@tpm_enum
class TPM_HR(UINT32):
    """Handle Ranges."""

    PCR = range(0x00000000, 0x00000020)
    NV_INDEX = range(0x01000000, 0x02000000)
    HMAC_SESSION = range(0x02000000, 0x02FFFFFF)
    POLICY_SESSION = range(0x03000000, 0x03FFFFFF)
    TRANSIENT = range(0x80000000, 0x80FFFFFE)
    PERSISTENT = range(0x81000000, 0x81FFFFFF)
    AC = range(0x90000000, 0x90010000)


@tpm_enum
class TPM_RS(UINT32):
    """Permanent Session Handles."""

    PW = 0x40000009


class TPM_HANDLE(UINT32):
    _valid_values = ValidValues(
        TPM_HR,
        TPM_RS,
        TPM_RH,
    )
