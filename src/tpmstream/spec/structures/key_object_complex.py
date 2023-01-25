from ..common.values import ValidValues, tpm_dataclass
from .algorithm_parameters_and_structures import (
    TPM2B_ECC_PARAMETER,
    TPM2B_PRIVATE_KEY_RSA,
    TPM2B_PUBLIC_KEY_RSA,
    TPM2B_SENSITIVE_DATA,
    TPM2B_SYM_KEY,
    TPMI_ECC_CURVE,
    TPMI_RSA_KEY_BITS,
    TPMS_DERIVE,
    TPMS_ECC_POINT,
    TPMS_SYMCIPHER_PARMS,
    TPMT_ASYM_SCHEME,
    TPMT_ECC_SCHEME,
    TPMT_KDF_SCHEME,
    TPMT_KEYEDHASH_SCHEME,
    TPMT_RSA_SCHEME,
    TPMT_SYM_DEF_OBJECT,
)
from .attribute_structures import TPMA_OBJECT
from .base_types import BYTE, UINT16, UINT32
from .constants import TPM_ALG, TPM_ALG_ID, AlgType
from .interface_types import TPMI_ALG_HASH
from .structures import TPM2B_AUTH, TPM2B_DIGEST


class TPMI_ALG_PUBLIC(TPM_ALG_ID):
    _valid_values = ValidValues(TPM_ALG.by_type_at_least(AlgType.Object))


@tpm_dataclass
class TPMU_PUBLIC_ID:
    _selected_by = {
        "keyedHash": TPM_ALG.KEYEDHASH,
        "sym": TPM_ALG.SYMCIPHER,
        "rsa": TPM_ALG.RSA,
        "ecc": TPM_ALG.ECC,
        "derive": None,
    }

    keyedHash: TPM2B_DIGEST
    sym: TPM2B_DIGEST
    rsa: TPM2B_PUBLIC_KEY_RSA
    ecc: TPMS_ECC_POINT
    derive: TPMS_DERIVE


@tpm_dataclass
class TPMS_KEYEDHASH_PARMS:
    scheme: TPMT_KEYEDHASH_SCHEME.plus()


@tpm_dataclass
class TPMS_ASYM_PARMS:
    symmetric: TPMT_SYM_DEF_OBJECT.plus()
    scheme: TPMT_ASYM_SCHEME.plus()


@tpm_dataclass
class TPMS_RSA_PARMS:
    symmetric: TPMT_SYM_DEF_OBJECT.plus()
    scheme: TPMT_RSA_SCHEME.plus()
    keyBits: TPMI_RSA_KEY_BITS
    exponent: UINT32


@tpm_dataclass
class TPMS_ECC_PARMS:
    symmetric: TPMT_SYM_DEF_OBJECT.plus()
    scheme: TPMT_ECC_SCHEME.plus()
    curveID: TPMI_ECC_CURVE
    kdf: TPMT_KDF_SCHEME.plus()


@tpm_dataclass
class TPMU_PUBLIC_PARMS:
    _selected_by = {
        "keyedHashDetail": TPM_ALG.KEYEDHASH,
        "symDetail": TPM_ALG.SYMCIPHER,
        "rsaDetail": TPM_ALG.RSA,
        "eccDetail": TPM_ALG.ECC,
        "asymDetail": None,
    }

    keyedHashDetail: TPMS_KEYEDHASH_PARMS
    symDetail: TPMS_SYMCIPHER_PARMS
    rsaDetail: TPMS_RSA_PARMS
    eccDetail: TPMS_ECC_PARMS
    asymDetail: TPMS_ASYM_PARMS


@tpm_dataclass
class TPMT_PUBLIC_PARMS:
    _selectors = {
        "parameters": "type",
    }

    type: TPMI_ALG_PUBLIC
    parameters: TPMU_PUBLIC_PARMS


@tpm_dataclass
class TPMT_PUBLIC:
    _selectors = {
        "parameters": "type",
        "unique": "type",
    }

    type: TPMI_ALG_PUBLIC
    nameAlg: TPMI_ALG_HASH  # TODO is optional
    objectAttributes: TPMA_OBJECT
    authPolicy: TPM2B_DIGEST
    parameters: TPMU_PUBLIC_PARMS
    unique: TPMU_PUBLIC_ID


@tpm_dataclass
class TPM2B_PUBLIC:
    size: UINT16
    publicArea: TPMT_PUBLIC  # TODO is optional


@tpm_dataclass
class TPM2B_TEMPLATE:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPM2B_PRIVATE_VENDOR_SPECIFIC:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMU_SENSITIVE_COMPOSITE:
    _selected_by = {
        "rsa": TPM_ALG.RSA,
        "ecc": TPM_ALG.ECC,
        "bits": TPM_ALG.KEYEDHASH,
        "sym": TPM_ALG.SYMCIPHER,
        "any": None,
    }

    rsa: TPM2B_PRIVATE_KEY_RSA
    ecc: TPM2B_ECC_PARAMETER
    bits: TPM2B_SENSITIVE_DATA
    sym: TPM2B_SYM_KEY
    any: TPM2B_PRIVATE_VENDOR_SPECIFIC


@tpm_dataclass
class TPMT_SENSITIVE:
    _selectors = {
        "sensitive": "sensitiveType",
    }

    sensitiveType: TPMI_ALG_PUBLIC
    authValue: TPM2B_AUTH  # TODO is optional
    seedValue: TPM2B_DIGEST
    sensitive: TPMU_SENSITIVE_COMPOSITE


@tpm_dataclass
class TPM2B_SENSITIVE:
    size: UINT16
    sensitiveArea: TPMT_SENSITIVE


# sic!
@tpm_dataclass
class _PRIVATE:
    integrityOuter: TPM2B_DIGEST
    integrityInner: TPM2B_DIGEST  # or TPM2B_IV
    sensitive: TPM2B_SENSITIVE


@tpm_dataclass
class TPM2B_PRIVATE:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMS_ID_OBJECT:
    integrityHMAC: TPM2B_DIGEST
    encIdentity: TPM2B_DIGEST


@tpm_dataclass
class TPM2B_ID_OBJECT:
    size: UINT16
    credential: list[BYTE]
