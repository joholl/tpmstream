from ..common.values import ValidValues
from .base_types import BOOL
from .constants import TPM_ALG, TPM_ALG_ID, TPM_ST, AlgType
from .handles import TPM_HANDLE, TPM_HR, TPM_RH, TPM_RS


class TPMI_YES_NO(BOOL):
    _valid_values = ValidValues(
        0,
        1,
    )


class TPMI_DH_OBJECT(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.TRANSIENT,
        TPM_HR.PERSISTENT,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_DH_PARENT(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.TRANSIENT,
        TPM_HR.PERSISTENT,
        TPM_RH.OWNER,
        TPM_RH.PLATFORM,
        TPM_RH.ENDORSEMENT,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_DH_PERSISTENT(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.PERSISTENT,
    )


class TPMI_DH_ENTITY(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.OWNER,
        TPM_RH.ENDORSEMENT,
        TPM_RH.PLATFORM,
        TPM_RH.LOCKOUT,
        TPM_HR.TRANSIENT,
        TPM_HR.PERSISTENT,
        TPM_HR.NV_INDEX,
        TPM_HR.PCR,
        TPM_RH.AUTH,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_DH_PCR(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.PCR,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_SH_AUTH_SESSION(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.HMAC_SESSION,
        TPM_HR.POLICY_SESSION,
        TPM_RS.PW,  # TODO is optional
    )


class TPMI_SH_HMAC(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.HMAC_SESSION,
    )


class TPMI_SH_POLICY(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.POLICY_SESSION,
    )


class TPMI_DH_CONTEXT(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.HMAC_SESSION,
        TPM_HR.POLICY_SESSION,
        TPM_HR.TRANSIENT,
    )


class TPMI_DH_SAVED(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.HMAC_SESSION,
        TPM_HR.POLICY_SESSION,
        TPM_HR.TRANSIENT.by_number(0x80000000),
        TPM_HR.TRANSIENT.by_number(0x80000001),
        TPM_HR.TRANSIENT.by_number(0x80000002),
    )


class TPMI_RH_HIERARCHY(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.OWNER,
        TPM_RH.PLATFORM,
        TPM_RH.ENDORSEMENT,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_RH_ENABLES(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.OWNER,
        TPM_RH.PLATFORM,
        TPM_RH.ENDORSEMENT,
        TPM_RH.PLATFORM_NV,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_RH_HIERARCHY_AUTH(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.OWNER,
        TPM_RH.PLATFORM,
        TPM_RH.ENDORSEMENT,
        TPM_RH.LOCKOUT,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_RH_HIERARCHY_POLICY(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.OWNER,
        TPM_RH.PLATFORM,
        TPM_RH.ENDORSEMENT,
        TPM_RH.LOCKOUT,
        TPM_RH.ACT,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_RH_PLATFORM(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.PLATFORM,
    )


class TPMI_RH_OWNER(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.OWNER,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_RH_ENDORSEMENT(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.ENDORSEMENT,
        TPM_RH.NULL,  # TODO is optional
    )


class TPMI_RH_PROVISION(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.OWNER,
        TPM_RH.PLATFORM,
    )


class TPMI_RH_CLEAR(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.LOCKOUT,
        TPM_RH.PLATFORM,
    )


class TPMI_RH_NV_AUTH(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.PLATFORM,
        TPM_RH.OWNER,
        TPM_HR.NV_INDEX,
    )


class TPMI_RH_LOCKOUT(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.LOCKOUT,
    )


class TPMI_RH_NV_INDEX(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.NV_INDEX,
    )


class TPMI_RH_AC(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_HR.AC,
    )


class TPMI_RH_ACT(TPM_HANDLE):
    _valid_values = ValidValues(
        TPM_RH.ACT,
    )


class TPMI_ALG_HASH(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Hash),
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ALG_ASYM(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Asymmetric, AlgType.Object),
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ALG_SYM(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Symmetric),
        TPM_ALG.XOR,
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ALG_SYM_OBJECT(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Symmetric),
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ALG_SYM_MODE(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Symmetric, AlgType.Encryption),
        TPM_ALG.by_type_exactly(AlgType.Symmetric, AlgType.Signing),
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ALG_KDF(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Hash, AlgType.MaskGeneration),
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ALG_SIG_SCHEME(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.Signing),
        TPM_ALG.HMAC,
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ECC_KEY_EXCHANGE(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_at_least(AlgType.Asymmetric, AlgType.MaskGeneration),
        TPM_ALG.SM2,
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ST_COMMAND_TAG(TPM_ST):
    _valid_values = ValidValues(
        TPM_ST.NO_SESSIONS,
        TPM_ST.SESSIONS,
    )


class TPMI_ALG_MAC_SCHEME(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Symmetric, AlgType.Signing),
        TPM_ALG.by_type_exactly(AlgType.Hash),
        TPM_ALG.NULL,  # TODO is optional
    )


class TPMI_ALG_CIPHER_MODE(TPM_ALG_ID):
    _valid_values = ValidValues(
        TPM_ALG.by_type_exactly(AlgType.Symmetric, AlgType.Encryption),
        TPM_ALG.NULL,  # TODO is optional
    )
