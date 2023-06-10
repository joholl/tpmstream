from ..common.values import tpm_bitfield, tpm_dataclass, tpm_enum
from .base_types import UINT8, UINT16, UINT32
from .interface_types import TPMI_ALG_HASH, TPMI_RH_NV_INDEX
from .structures import TPM2B_DIGEST


# 4-bit only
@tpm_enum
class TPM_NT(UINT8):
    ORDINARY = 0x0
    COUNTER = 0x1
    BITS = 0x2
    EXTEND = 0x4
    PIN_FAIL = 0x8
    PIN_PASS = 0x9


@tpm_dataclass
class TPMS_NV_PIN_COUNTER_PARAMETERS:
    pinCount: UINT32
    pinLimit: UINT32


@tpm_bitfield()
class TPMA_NV(UINT32):
    PPWRITE = 0x00000001
    OWNERWRITE = 0x00000002
    AUTHWRITE = 0x00000004
    POLICYWRITE = 0x00000008
    TPM_NT = 0x000000F0
    reserved0 = 0x00000300
    POLICY_DELETE = 0x00000400
    WRITELOCKED = 0x00000800
    WRITEALL = 0x00001000
    WRITEDEFINE = 0x00002000
    WRITE_STCLEAR = 0x00004000
    GLOBALLOCK = 0x00008000
    PPREAD = 0x00010000
    OWNERREAD = 0x00020000
    AUTHREAD = 0x00040000
    POLICYREAD = 0x00080000
    reserved1 = 0x01F00000
    NO_DA = 0x02000000
    ORDERLY = 0x04000000
    CLEAR_STCLEAR = 0x08000000
    READLOCKED = 0x10000000
    WRITTEN = 0x20000000
    PLATFORMCREATE = 0x40000000
    READ_STCLEAR = 0x80000000


@tpm_dataclass
class TPMS_NV_PUBLIC:
    nvIndex: TPMI_RH_NV_INDEX
    nameAlg: TPMI_ALG_HASH
    attributes: TPMA_NV
    authPolicy: TPM2B_DIGEST
    dataSize: UINT16


@tpm_dataclass
class TPM2B_NV_PUBLIC:
    size: UINT16
    nvPublic: TPMS_NV_PUBLIC
