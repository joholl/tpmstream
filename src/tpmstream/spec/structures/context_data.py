from tpmstream.spec.common.values import tpm_dataclass
from tpmstream.spec.structures.base_types import BYTE, UINT16, UINT64
from tpmstream.spec.structures.interface_types import TPMI_DH_SAVED, TPMI_RH_HIERARCHY
from tpmstream.spec.structures.structures import TPM2B_DIGEST


@tpm_dataclass
class TPM2B_CONTEXT_SENSITIVE:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMS_CONTEXT_DATA:
    integrity: TPM2B_DIGEST
    encrypted: TPM2B_CONTEXT_SENSITIVE


@tpm_dataclass
class TPM2B_CONTEXT_DATA:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMS_CONTEXT:
    sequence: UINT64
    savedHandle: TPMI_DH_SAVED
    hierarchy: TPMI_RH_HIERARCHY.plus()
    contextBlob: TPM2B_CONTEXT_DATA
