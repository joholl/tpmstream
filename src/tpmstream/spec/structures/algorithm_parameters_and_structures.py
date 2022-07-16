from ..common.values import ValidValues, tpm_dataclass
from .base_types import BYTE, TPM_KEY_BITS, UINT16
from .constants import TPM_ALG, TPM_ALG_ID, TPM_ECC_CURVE, AlgType
from .interface_types import (
    TPMI_ALG_HASH,
    TPMI_ALG_KDF,
    TPMI_ALG_SIG_SCHEME,
    TPMI_ALG_SYM,
    TPMI_ALG_SYM_MODE,
    TPMI_ALG_SYM_OBJECT,
)
from .structures import TPM2B_AUTH, TPMS_EMPTY, TPMT_HA


# For all !ALG.S (i.e. symmetric-only) algorithms
class TPMI_TDES_KEY_BITS(TPM_KEY_BITS):
    pass


class TPMI_AES_KEY_BITS(TPM_KEY_BITS):
    pass


class TPMI_SM4_KEY_BITS(TPM_KEY_BITS):
    pass


class TPMI_CAMELLIA_KEY_BITS(TPM_KEY_BITS):
    pass


@tpm_dataclass
class TPMU_SYM_KEY_BITS:
    _selected_by = {
        "tdes": TPM_ALG.TDES,
        "aes": TPM_ALG.AES,
        "sm4": TPM_ALG.SM4,
        "camellia": TPM_ALG.CAMELLIA,
        "sym": TPM_KEY_BITS,
        "xor": TPM_ALG.XOR,
        "null": TPM_ALG.NULL,
    }

    tdes: TPMI_TDES_KEY_BITS
    aes: TPMI_AES_KEY_BITS
    sm4: TPMI_SM4_KEY_BITS
    camellia: TPMI_CAMELLIA_KEY_BITS
    sym: TPM_KEY_BITS
    xor: TPMI_ALG_HASH
    null: None


@tpm_dataclass
class TPMU_SYM_MODE:
    _selected_by = {
        "tdes": TPM_ALG.TDES,
        "aes": TPM_ALG.AES,
        "sm4": TPM_ALG.SM4,
        "camellia": TPM_ALG.CAMELLIA,
        "sym": None,
        "xor": TPM_ALG.XOR,
        "null": TPM_ALG.NULL,
    }

    tdes: TPMI_ALG_SYM_MODE.plus()
    aes: TPMI_ALG_SYM_MODE.plus()
    sm4: TPMI_ALG_SYM_MODE.plus()
    camellia: TPMI_ALG_SYM_MODE.plus()
    sym: TPMI_ALG_SYM_MODE.plus()
    xor: None
    null: None


@tpm_dataclass
class TPMU_SYM_DETAILS:
    _selected_by = {
        "tdes": TPM_ALG.TDES,
        "aes": TPM_ALG.AES,
        "sm4": TPM_ALG.SM4,
        "camellia": TPM_ALG.CAMELLIA,
        "sym": None,
        "xor": TPM_ALG.XOR,
        "null": TPM_ALG.NULL,
    }

    tdes: None
    aes: None
    sm4: None
    camellia: None
    sym: None
    xor: None
    null: None


@tpm_dataclass
class TPMT_SYM_DEF:
    _selectors = {
        "keyBits": "algorithm",
        "mode": "algorithm",
        "details": "algorithm",
    }

    algorithm: TPMI_ALG_SYM  # TODO is optional
    keyBits: TPMU_SYM_KEY_BITS
    mode: TPMU_SYM_MODE
    details: TPMU_SYM_DETAILS


@tpm_dataclass
class TPMT_SYM_DEF_OBJECT:
    _selectors = {
        "keyBits": "algorithm",
        "mode": "algorithm",
        "details": "algorithm",
    }

    algorithm: TPMI_ALG_SYM_OBJECT  # TODO is optional
    keyBits: TPMU_SYM_KEY_BITS
    mode: TPMU_SYM_MODE
    details: TPMU_SYM_DETAILS


@tpm_dataclass
class TPM2B_SYM_KEY:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMS_SYMCIPHER_PARMS:
    sym: TPMT_SYM_DEF_OBJECT


@tpm_dataclass
class TPM2B_LABEL:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMS_DERIVE:
    label: TPM2B_LABEL
    context: TPM2B_LABEL


@tpm_dataclass
class TPM2B_DERIVE:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMU_SENSITIVE_CREATE:
    # TODO selection determined by context???
    _selected_by = {
        "create": None,
        "derive": None,
    }

    create: list[BYTE]
    derive: TPMS_DERIVE


@tpm_dataclass
class TPM2B_SENSITIVE_DATA:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMS_SENSITIVE_CREATE:
    userAuth: TPM2B_AUTH
    data: TPM2B_SENSITIVE_DATA


@tpm_dataclass
class TPM2B_SENSITIVE_CREATE:
    size: UINT16
    sensitive: TPMS_SENSITIVE_CREATE


@tpm_dataclass
class TPMS_SCHEME_HASH:
    hashAlg: TPMI_ALG_HASH


@tpm_dataclass
class TPMS_SCHEME_ECDAA:
    hashAlg: TPMI_ALG_HASH
    count: UINT16


class TPMI_ALG_KEYEDHASH_SCHEME(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.HMAC,
        TPM_ALG.XOR,
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMS_SCHEME_HMAC(TPMS_SCHEME_HASH):
    pass


@tpm_dataclass
class TPMS_SCHEME_XOR:
    hashAlg: TPMI_ALG_HASH
    kdf: TPMI_ALG_KDF.plus()


@tpm_dataclass
class TPMU_SCHEME_KEYEDHASH:
    _selected_by = {
        "hmac": TPM_ALG.HMAC,
        "xor": TPM_ALG.XOR,
        "null": TPM_ALG.NULL,
    }

    hmac: TPMS_SCHEME_HMAC
    xor: TPMS_SCHEME_XOR
    null: None


@tpm_dataclass
class TPMT_KEYEDHASH_SCHEME:
    _selectors = {
        "details": "scheme",
    }

    scheme: TPMI_ALG_KEYEDHASH_SCHEME  # TODO is optional
    details: TPMU_SCHEME_KEYEDHASH


# For all !ALG.AX (i.e. asymmetric + signing) algorithms only
class TPMS_SIG_SCHEME_ECDSA(TPMS_SCHEME_HASH):
    pass


class TPMS_SIG_SCHEME_ECSCHNORR(TPMS_SCHEME_HASH):
    pass


class TPMS_SIG_SCHEME_RSAPSS(TPMS_SCHEME_HASH):
    pass


class TPMS_SIG_SCHEME_RSASSA(TPMS_SCHEME_HASH):
    pass


class TPMS_SIG_SCHEME_SM2(TPMS_SCHEME_HASH):
    pass


# For all !ALG.AXN (i.e. asymmetric + signing + anonymous) algorithms only
class TPMS_SIG_SCHEME_ECDAA(TPMS_SCHEME_ECDAA):
    pass


# TODO can we get rid of all these None literals? (maybe initialize them with None? or decorator arg?)
# TODO see https://docs.python.org/3/library/dataclasses.html
@tpm_dataclass
class TPMU_SIG_SCHEME:
    _selected_by = {
        "ecdaa": TPM_ALG.ECDAA,
        "ecdsa": TPM_ALG.ECDSA,
        "ecschnorr": TPM_ALG.ECSCHNORR,
        "rsapss": TPM_ALG.RSAPSS,
        "rsassa": TPM_ALG.RSASSA,
        "sm2": TPM_ALG.SM2,
        "hmac": TPM_ALG.HMAC,
        "any": None,
        "null": TPM_ALG.NULL,
    }

    ecdaa: TPMS_SIG_SCHEME_ECDAA
    ecdsa: TPMS_SIG_SCHEME_ECDSA
    ecschnorr: TPMS_SIG_SCHEME_ECSCHNORR
    rsapss: TPMS_SIG_SCHEME_RSAPSS
    rsassa: TPMS_SIG_SCHEME_RSASSA
    sm2: TPMS_SIG_SCHEME_SM2
    hmac: TPMS_SCHEME_HMAC
    any: TPMS_SCHEME_HASH
    null: None


@tpm_dataclass
class TPMT_SIG_SCHEME:
    _selectors = {
        "details": "scheme",
    }

    scheme: TPMI_ALG_SIG_SCHEME  # TODO is optional
    details: TPMU_SIG_SCHEME


# For all !ALG.AEH (i.e. asymmetric + encryption + hash) algorithms only
class TPMS_ENC_SCHEME_OAEP(TPMS_SCHEME_HASH):
    pass


# For all !ALG.AE (i.e. asymmetric + encryption) algorithms only
class TPMS_ENC_SCHEME_RSAES(TPMS_EMPTY):
    pass


# For all !ALG.AM (i.e. asymmetric + mask generation) algorithms only
class TPMS_KEY_SCHEME_ECDH(TPMS_SCHEME_HASH):
    pass


class TPMS_KEY_SCHEME_ECMQV(TPMS_SCHEME_HASH):
    pass


# For all !ALG.HM (i.e. hash + mask generation) algorithms only
class TPMS_SCHEME_MGF1(TPMS_SCHEME_HASH):
    pass


class TPMS_SCHEME_KDF1_SP800_108(TPMS_SCHEME_HASH):
    pass


class TPMS_SCHEME_KDF1_SP800_56A(TPMS_SCHEME_HASH):
    pass


class TPMS_SCHEME_KDF2(TPMS_SCHEME_HASH):
    pass


@tpm_dataclass
class TPMU_KDF_SCHEME:
    _selected_by = {
        "mgf1": TPM_ALG.MGF1,
        "kdf1_sp800_108": TPM_ALG.KDF1_SP800_108,
        "kdf1_sp800_56a": TPM_ALG.KDF1_SP800_56A,
        "kdf2": TPM_ALG.KDF2,
        "null": TPM_ALG.NULL,
    }

    mgf1: TPMS_SCHEME_MGF1
    kdf1_sp800_108: TPMS_SCHEME_KDF1_SP800_108
    kdf1_sp800_56a: TPMS_SCHEME_KDF1_SP800_56A
    kdf2: TPMS_SCHEME_KDF2
    null: None


@tpm_dataclass
class TPMT_KDF_SCHEME:
    _selectors = {
        "details": "scheme",
    }

    scheme: TPMI_ALG_KDF  # TODO is optional
    details: TPMU_KDF_SCHEME


class TPMI_ALG_ASYM_SCHEME(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.MaskGeneration),
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.Signing),
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.Encryption),
        TPM_ALG.NULL,  # TODO is optional
    )


@tpm_dataclass
class TPMU_ASYM_SCHEME:
    _selected_by = {
        "ecdh": TPM_ALG.ECDH,
        "ecmqv": TPM_ALG.ECMQV,
        "ecdaa": TPM_ALG.ECDAA,
        "ecdsa": TPM_ALG.ECDSA,
        "ecschnorr": TPM_ALG.ECSCHNORR,
        "rsapss": TPM_ALG.RSAPSS,
        "rsassa": TPM_ALG.RSASSA,
        "sm2": TPM_ALG.SM2,
        "oaep": TPM_ALG.OAEP,
        "rsaes": TPM_ALG.RSAES,
        "anySig": None,
        "null": TPM_ALG.NULL,
    }

    ecdh: TPMS_KEY_SCHEME_ECDH
    ecmqv: TPMS_KEY_SCHEME_ECMQV
    ecdaa: TPMS_SIG_SCHEME_ECDAA
    ecdsa: TPMS_SIG_SCHEME_ECDSA
    ecschnorr: TPMS_SIG_SCHEME_ECSCHNORR
    rsapss: TPMS_SIG_SCHEME_RSAPSS
    rsassa: TPMS_SIG_SCHEME_RSASSA
    sm2: TPMS_SIG_SCHEME_SM2
    oaep: TPMS_ENC_SCHEME_OAEP
    rsaes: TPMS_ENC_SCHEME_RSAES
    anySig: TPMS_SCHEME_HASH
    null: None


@tpm_dataclass
class TPMT_ASYM_SCHEME:
    _selectors = {
        "details": "scheme",
    }

    scheme: TPMI_ALG_ASYM_SCHEME  # TODO is optional
    details: TPMU_ASYM_SCHEME


class TPMI_ALG_RSA_SCHEME(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.Encryption),
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.Signing),
        TPM_ALG.NULL,  # TODO is optional
    )


@tpm_dataclass
class TPMT_RSA_SCHEME:
    _selectors = {
        "details": "scheme",
    }

    scheme: TPMI_ALG_RSA_SCHEME  # TODO is optional
    details: TPMU_ASYM_SCHEME


class TPMI_ALG_RSA_DECRYPT(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.Encryption),
        TPM_ALG.NULL,  # TODO is optional
    )


@tpm_dataclass
class TPMT_RSA_DECRYPT:
    _selectors = {
        "details": "scheme",
    }

    scheme: TPMI_ALG_RSA_DECRYPT  # TODO is optional
    details: TPMU_ASYM_SCHEME


@tpm_dataclass
class TPM2B_PUBLIC_KEY_RSA:
    size: UINT16
    buffer: list[BYTE]


class TPMI_RSA_KEY_BITS(TPM_KEY_BITS):
    _valid_values = ValidValues(1024, 2048, 3072, 4096)


@tpm_dataclass
class TPM2B_PRIVATE_KEY_RSA:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPM2B_ECC_PARAMETER:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMS_ECC_POINT:
    x: TPM2B_ECC_PARAMETER
    y: TPM2B_ECC_PARAMETER


@tpm_dataclass
class TPM2B_ECC_POINT:
    size: UINT16
    point: TPMS_ECC_POINT


class TPMI_ALG_ECC_SCHEME(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.Signing),
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.MaskGeneration),
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ECC_CURVE(TPM_ECC_CURVE):
    pass


@tpm_dataclass
class TPMT_ECC_SCHEME:
    _selectors = {
        "details": "scheme",
    }

    scheme: TPMI_ALG_ECC_SCHEME  # TODO is optional
    details: TPMU_ASYM_SCHEME


@tpm_dataclass
class TPMS_ALGORITHM_DETAIL_ECC:
    curveID: TPM_ECC_CURVE
    keySize: UINT16
    kdf: TPMT_KDF_SCHEME.plus()
    sign: TPMT_ECC_SCHEME.plus()
    p: TPM2B_ECC_PARAMETER
    a: TPM2B_ECC_PARAMETER
    b: TPM2B_ECC_PARAMETER
    gX: TPM2B_ECC_PARAMETER
    gY: TPM2B_ECC_PARAMETER
    n: TPM2B_ECC_PARAMETER
    h: TPM2B_ECC_PARAMETER


@tpm_dataclass
class TPMS_SIGNATURE_RSA:
    hash: TPMI_ALG_HASH
    sig: TPM2B_PUBLIC_KEY_RSA


# For all RSA !ALG.ax (i.e. at least asymmetric signing) algorithms
class TPMS_SIGNATURE_RSAPSS(TPMS_SIGNATURE_RSA):
    pass


class TPMS_SIGNATURE_RSASSA(TPMS_SIGNATURE_RSA):
    pass


@tpm_dataclass
class TPMS_SIGNATURE_ECC:
    hash: TPMI_ALG_HASH
    signatureR: TPM2B_ECC_PARAMETER
    signatureS: TPM2B_ECC_PARAMETER


# For all ECC !ALG.ax (i.e. at least asymmetric signing) algorithms
class TPMS_SIGNATURE_ECDAA(TPMS_SIGNATURE_ECC):
    pass


class TPMS_SIGNATURE_ECDSA(TPMS_SIGNATURE_ECC):
    pass


class TPMS_SIGNATURE_ECSCHNORR(TPMS_SIGNATURE_ECC):
    pass


class TPMS_SIGNATURE_SM2(TPMS_SIGNATURE_ECC):
    pass


@tpm_dataclass
class TPMU_SIGNATURE:
    _selected_by = {
        "ecdaa": TPM_ALG.ECDAA,
        "ecdsa": TPM_ALG.ECDSA,
        "ecschnorr": TPM_ALG.ECSCHNORR,
        "rsapss": TPM_ALG.RSAPSS,
        "rsassa": TPM_ALG.RSASSA,
        "sm2": TPM_ALG.SM2,
        "hmac": TPM_ALG.HMAC,
        "any": None,
        "null": TPM_ALG.NULL,
    }

    ecdaa: TPMS_SIGNATURE_ECDAA
    ecdsa: TPMS_SIGNATURE_ECDSA
    ecschnorr: TPMS_SIGNATURE_ECSCHNORR
    rsapss: TPMS_SIGNATURE_RSAPSS
    rsassa: TPMS_SIGNATURE_RSASSA
    sm2: TPMS_SIGNATURE_SM2
    hmac: TPMT_HA
    any: TPMS_SCHEME_HASH
    null: None


@tpm_dataclass
class TPMT_SIGNATURE:
    _selectors = {
        "signature": "sigAlg",
    }

    sigAlg: TPMI_ALG_SIG_SCHEME  # TODO is optional
    signature: TPMU_SIGNATURE


@tpm_dataclass
class TPMU_ENCRYPTED_SECRET:
    _selected_by = {
        "ecc": TPM_ALG.ECC,
        "rsa": TPM_ALG.RSA,
        "symmetric": TPM_ALG.SYMCIPHER,
        "keyedHash": TPM_ALG.KEYEDHASH,
    }

    ecc: list[BYTE]
    rsa: list[BYTE]
    symmetric: list[BYTE]
    keyedHash: list[BYTE]


@tpm_dataclass
class TPM2B_ENCRYPTED_SECRET:
    size: UINT16
    secret: list[BYTE]
