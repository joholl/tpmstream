from enum import IntEnum, auto

from ..common.base_type import numeric
from ..common.tpm_rc import TPM_RC
from ..common.values import tpm_enum
from .base_types import INT8, UINT8, UINT16, UINT32


@tpm_enum
class TPM_SPEC(UINT32):
    FAMILY = 0x322E3000
    LEVEL = 00
    VERSION = 159
    YEAR = 2020
    DAY_OF_YEAR = 170


@tpm_enum
class TPM_GENERATED(UINT32):
    VALUE = 0xFF544347


class AlgType(IntEnum):
    Asymmetric = auto()
    Symmetric = auto()
    Hash = auto()
    Signing = auto()
    AnonymousSigning = auto()
    Encryption = auto()
    MaskGeneration = auto()
    Object = auto()


@numeric
class AlgValue:
    def __init__(self, value, *types):
        self._value = value
        self._types = types

    def to_bytes(self, *args, **kwargs):
        return self._value.to_bytes(*args, **kwargs)


# TODO use *args instead of tuples
@tpm_enum
class TPM_ALG(UINT16):
    ERROR = AlgValue(0x0000)
    RSA = AlgValue(0x0001, AlgType.Asymmetric, AlgType.Object)
    TDES = AlgValue(0x0003, AlgType.Symmetric)
    SHA = AlgValue(0x0004, AlgType.Hash)
    SHA1 = AlgValue(0x0004, AlgType.Hash)
    HMAC = AlgValue(0x0005, AlgType.Hash, AlgType.Signing)
    AES = AlgValue(0x0006, AlgType.Symmetric)
    MGF1 = AlgValue(0x0007, AlgType.Hash, AlgType.MaskGeneration)
    KEYEDHASH = AlgValue(0x0008, AlgType.Hash, AlgType.Object)
    XOR = AlgValue(0x000A, AlgType.Hash, AlgType.Symmetric)
    SHA256 = AlgValue(0x000B, AlgType.Hash)
    SHA384 = AlgValue(0x000C, AlgType.Hash)
    SHA512 = AlgValue(0x000D, AlgType.Hash)
    NULL = AlgValue(0x0010)
    SM3_256 = AlgValue(0x0012, AlgType.Hash)
    SM4 = AlgValue(0x0013, AlgType.Symmetric)
    RSASSA = AlgValue(0x0014, AlgType.Asymmetric, AlgType.Signing)
    RSAES = AlgValue(0x0015, AlgType.Asymmetric, AlgType.Encryption)
    RSAPSS = AlgValue(0x0016, AlgType.Asymmetric, AlgType.Signing)
    OAEP = AlgValue(0x0017, AlgType.Asymmetric, AlgType.Encryption, AlgType.Hash)
    ECDSA = AlgValue(0x0018, AlgType.Asymmetric, AlgType.Signing)
    ECDH = AlgValue(0x0019, AlgType.Asymmetric, AlgType.MaskGeneration)
    ECDAA = AlgValue(
        0x001A, AlgType.Asymmetric, AlgType.Signing, AlgType.AnonymousSigning
    )
    SM2 = AlgValue(0x001B, AlgType.Asymmetric, AlgType.Signing)
    ECSCHNORR = AlgValue(0x001C, AlgType.Asymmetric, AlgType.Signing)
    ECMQV = AlgValue(0x001D, AlgType.Asymmetric, AlgType.MaskGeneration)
    KDF1_SP800_56A = AlgValue(0x0020, AlgType.Hash, AlgType.MaskGeneration)
    KDF2 = AlgValue(0x0021, AlgType.Hash, AlgType.MaskGeneration)
    KDF1_SP800_108 = AlgValue(0x0022, AlgType.Hash, AlgType.MaskGeneration)
    ECC = AlgValue(0x0023, AlgType.Asymmetric, AlgType.Object)
    SYMCIPHER = AlgValue(0x0025, AlgType.Object, AlgType.Symmetric)
    CAMELLIA = AlgValue(0x0026, AlgType.Symmetric)
    SHA3_256 = AlgValue(0x0027, AlgType.Hash)
    SHA3_384 = AlgValue(0x0028, AlgType.Hash)
    SHA3_512 = AlgValue(0x0029, AlgType.Hash)
    CMAC = AlgValue(0x003F, AlgType.Symmetric, AlgType.Encryption)
    CTR = AlgValue(0x0040, AlgType.Symmetric, AlgType.Encryption)
    OFB = AlgValue(0x0041, AlgType.Symmetric, AlgType.Encryption)
    CBC = AlgValue(0x0042, AlgType.Symmetric, AlgType.Encryption)
    CFB = AlgValue(0x0043, AlgType.Symmetric, AlgType.Encryption)
    ECB = AlgValue(0x0044, AlgType.Symmetric, AlgType.Encryption)

    @classmethod
    def by_type_at_least(cls, *types) -> list[AlgValue]:
        """Return all AlgValues which have at least the given types. !ALG.ax is at last asymmetric and signing."""
        # filter for types
        return cls.filter(
            lambda _name, attr: all(t in attr._value._types for t in types)
        )

    @classmethod
    def by_type_exactly(cls, *types) -> list[AlgValue]:
        """Return all AlgValues which match exactly the given types. !ALG.AX is at exactly asymmetric and signing."""
        # filter for types
        return cls.filter(
            lambda _name, attr: all(t in attr._value._types for t in types)
            and len(types) == len(attr._value._types)
        )


class TPM_ALG_ID(TPM_ALG):
    pass


@tpm_enum
class TPM_ECC_CURVE(UINT16):
    NONE = 0x0000  # TODO is optional
    NIST_P192 = 0x0001
    NIST_P224 = 0x0002
    NIST_P256 = 0x0003
    NIST_P384 = 0x0004
    NIST_P521 = 0x0005
    BN_P256 = 0x0010
    BN_P638 = 0x0011
    SM2_P256 = 0x0020


@tpm_enum
class TPM_CC(UINT32):
    NV_UndefineSpaceSpecial = 0x0000011F
    EvictControl = 0x00000120
    HierarchyControl = 0x00000121
    NV_UndefineSpace = 0x00000122
    ChangeEPS = 0x00000124
    ChangePPS = 0x00000125
    Clear = 0x00000126
    ClearControl = 0x00000127
    ClockSet = 0x00000128
    HierarchyChangeAuth = 0x00000129
    NV_DefineSpace = 0x0000012A
    PCR_Allocate = 0x0000012B
    PCR_SetAuthPolicy = 0x0000012C
    PP_Commands = 0x0000012D
    SetPrimaryPolicy = 0x0000012E
    FieldUpgradeStart = 0x0000012F
    ClockRateAdjust = 0x00000130
    CreatePrimary = 0x00000131
    NV_GlobalWriteLock = 0x00000132
    GetCommandAuditDigest = 0x00000133
    NV_Increment = 0x00000134
    NV_SetBits = 0x00000135
    NV_Extend = 0x00000136
    NV_Write = 0x00000137
    NV_WriteLock = 0x00000138
    DictionaryAttackLockReset = 0x00000139
    DictionaryAttackParameters = 0x0000013A
    NV_ChangeAuth = 0x0000013B
    PCR_Event = 0x0000013C
    PCR_Reset = 0x0000013D
    SequenceComplete = 0x0000013E
    SetAlgorithmSet = 0x0000013F
    SetCommandCodeAuditStatus = 0x00000140
    FieldUpgradeData = 0x00000141
    IncrementalSelfTest = 0x00000142
    SelfTest = 0x00000143
    Startup = 0x00000144
    Shutdown = 0x00000145
    StirRandom = 0x00000146
    ActivateCredential = 0x00000147
    Certify = 0x00000148
    PolicyNV = 0x00000149
    CertifyCreation = 0x0000014A
    Duplicate = 0x0000014B
    GetTime = 0x0000014C
    GetSessionAuditDigest = 0x0000014D
    NV_Read = 0x0000014E
    NV_ReadLock = 0x0000014F
    ObjectChangeAuth = 0x00000150
    PolicySecret = 0x00000151
    Rewrap = 0x00000152
    Create = 0x00000153
    ECDH_ZGen = 0x00000154
    HMAC = 0x00000155
    Import = 0x00000156
    Load = 0x00000157
    Quote = 0x00000158
    RSA_Decrypt = 0x00000159
    HMAC_Start = 0x0000015B
    SequenceUpdate = 0x0000015C
    Sign = 0x0000015D
    Unseal = 0x0000015E
    PolicySigned = 0x00000160
    ContextLoad = 0x00000161
    ContextSave = 0x00000162
    ECDH_KeyGen = 0x00000163
    EncryptDecrypt = 0x00000164
    FlushContext = 0x00000165
    LoadExternal = 0x00000167
    MakeCredential = 0x00000168
    NV_ReadPublic = 0x00000169
    PolicyAuthorize = 0x0000016A
    PolicyAuthValue = 0x0000016B
    PolicyCommandCode = 0x0000016C
    PolicyCounterTimer = 0x0000016D
    PolicyCpHash = 0x0000016E
    PolicyLocality = 0x0000016F
    PolicyNameHash = 0x00000170
    PolicyOR = 0x00000171
    PolicyTicket = 0x00000172
    ReadPublic = 0x00000173
    RSA_Encrypt = 0x00000174
    StartAuthSession = 0x00000176
    VerifySignature = 0x00000177
    ECC_Parameters = 0x00000178
    FirmwareRead = 0x00000179
    GetCapability = 0x0000017A
    GetRandom = 0x0000017B
    GetTestResult = 0x0000017C
    Hash = 0x0000017D
    PCR_Read = 0x0000017E
    PolicyPCR = 0x0000017F
    PolicyRestart = 0x00000180
    ReadClock = 0x00000181
    PCR_Extend = 0x00000182
    PCR_SetAuthValue = 0x00000183
    NV_Certify = 0x00000184
    EventSequenceComplete = 0x00000185
    HashSequenceStart = 0x00000186
    PolicyPhysicalPresence = 0x00000187
    PolicyDuplicationSelect = 0x00000188
    PolicyGetDigest = 0x00000189
    TestParms = 0x0000018A
    Commit = 0x0000018B
    PolicyPassword = 0x0000018C
    ZGen_2Phase = 0x0000018D
    EC_Ephemeral = 0x0000018E
    PolicyNvWritten = 0x0000018F
    PolicyTemplate = 0x00000190
    CreateLoaded = 0x00000191
    PolicyAuthorizeNV = 0x00000192
    EncryptDecrypt2 = 0x00000193
    AC_GetCapability = 0x00000194
    AC_Send = 0x00000195
    Policy_AC_SendSelect = 0x00000196
    CertifyX509 = 0x00000197
    ACT_SetTimeout = 0x00000198


# TPM_RC is a combination of bitfield and enum and outsourced due to the required special handling
TPM_RC = TPM_RC


@tpm_enum
class TPM_CLOCK(INT8):
    """TPM_CLOCK_ADJUST type (renamed to match member naming)."""

    COARSE_SLOWER = -3
    MEDIUM_SLOWER = -2
    FINE_SLOWER = -1
    NO_CHANGE = 0
    FINE_FASTER = 1
    MEDIUM_FASTER = 2
    COARSE_FASTER = 3


class TPM_CLOCK_ADJUST(TPM_CLOCK):
    pass


@tpm_enum
class TPM_EO(UINT16):
    EQ = 0x0000
    NEQ = 0x0001
    SIGNED_GT = 0x0002
    UNSIGNED_GT = 0x0003
    SIGNED_LT = 0x0004
    UNSIGNED_LT = 0x0005
    SIGNED_GE = 0x0006
    UNSIGNED_GE = 0x0007
    SIGNED_LE = 0x0008
    UNSIGNED_LE = 0x0009
    BITSET = 0x000A
    BITCLEAR = 0x000B


@tpm_enum
class TPM_ST(UINT16):
    RSP_COMMAND = 0x00C4
    NULL = 0x8000
    NO_SESSIONS = 0x8001
    SESSIONS = 0x8002
    ATTEST_NV = 0x8014
    ATTEST_COMMAND_AUDIT = 0x8015
    ATTEST_SESSION_AUDIT = 0x8016
    ATTEST_CERTIFY = 0x8017
    ATTEST_QUOTE = 0x8018
    ATTEST_TIME = 0x8019
    ATTEST_CREATION = 0x801A
    ATTEST_NV_DIGEST = 0x801C
    CREATION = 0x8021
    VERIFIED = 0x8022
    AUTH_SECRET = 0x8023
    HASHCHECK = 0x8024
    AUTH_SIGNED = 0x8025
    FU_MANIFEST = 0x8029


@tpm_enum
class TPM_SU(UINT16):
    CLEAR = 0x0000
    STATE = 0x0001


@tpm_enum
class TPM_SE(UINT8):
    HMAC = 0x00
    POLICY = 0x01
    TRIAL = 0x03


@tpm_enum
class TPM_CAP(UINT32):
    ALGS = 0x00000000
    HANDLES = 0x00000001
    COMMANDS = 0x00000002
    PP_COMMANDS = 0x00000003
    AUDIT_COMMANDS = 0x00000004
    PCRS = 0x00000005
    TPM_PROPERTIES = 0x00000006
    PCR_PROPERTIES = 0x00000007
    ECC_CURVES = 0x00000008
    AUTH_POLICIES = 0x00000009
    ACT = 0x0000000A
    VENDOR_PROPERTY = 0x00000100


@tpm_enum
class TPM_PT(UINT32):
    NONE = 0x00000000
    FAMILY_INDICATOR = 0x00000100
    LEVEL = 0x00000101
    REVISION = 0x00000102
    DAY_OF_YEAR = 0x00000103
    YEAR = 0x00000104
    MANUFACTURER = 0x00000105
    VENDOR_STRING_1 = 0x00000106
    VENDOR_STRING_2 = 0x00000107
    VENDOR_STRING_3 = 0x00000108
    VENDOR_STRING_4 = 0x00000109
    VENDOR_TPM_TYPE = 0x00000110
    FIRMWARE_VERSION_1 = 0x00000111
    FIRMWARE_VERSION_2 = 0x00000112
    INPUT_BUFFER = 0x00000113
    HR_TRANSIENT_MIN = 0x00000114
    HR_PERSISTENT_MIN = 0x00000115
    HR_LOADED_MIN = 0x00000116
    ACTIVE_SESSIONS_MAX = 0x00000117
    PCR_COUNT = 0x00000118
    PCR_SELECT_MIN = 0x00000119
    CONTEXT_GAP_MAX = 0x00000120
    NV_COUNTERS_MAX = 0x00000122
    NV_INDEX_MAX = 0x00000123
    MEMORY = 0x00000124
    CLOCK_UPDATE = 0x00000125
    CONTEXT_HASH = 0x00000126
    CONTEXT_SYM = 0x00000127
    CONTEXT_SYM_SIZE = 0x00000128
    ORDERLY_COUNT = 0x00000129
    MAX_COMMAND_SIZE = 0x00000130
    MAX_RESPONSE_SIZE = 0x00000131
    MAX_DIGEST = 0x00000132
    MAX_OBJECT_CONTEXT = 0x00000133
    MAX_SESSION_CONTEXT = 0x00000134
    PS_FAMILY_INDICATOR = 0x00000135
    PS_LEVEL = 0x00000136
    PS_REVISION = 0x00000137
    PS_DAY_OF_YEAR = 0x00000138
    PS_YEAR = 0x00000139
    SPLIT_MAX = 0x00000140
    TOTAL_COMMANDS = 0x00000141
    LIBRARY_COMMANDS = 0x00000142
    VENDOR_COMMANDS = 0x00000143
    NV_BUFFER_MAX = 0x00000144
    MODES = 0x00000145
    MAX_CAP_BUFFER = 0x00000146
    PERMANENT = 0x00000200
    STARTUP_CLEAR = 0x00000201
    HR_NV_INDEX = 0x00000202
    HR_LOADED = 0x00000203
    HR_LOADED_AVAIL = 0x00000204
    HR_ACTIVE = 0x00000205
    HR_ACTIVE_AVAIL = 0x00000206
    HR_TRANSIENT_AVAIL = 0x00000207
    HR_PERSISTENT = 0x00000208
    HR_PERSISTENT_AVAIL = 0x00000209
    NV_COUNTERS = 0x00000210
    NV_COUNTERS_AVAIL = 0x00000211
    ALGORITHM_SET = 0x00000212
    LOADED_CURVES = 0x00000213
    LOCKOUT_COUNTER = 0x00000214
    MAX_AUTH_FAIL = 0x00000215
    LOCKOUT_INTERVAL = 0x00000216
    LOCKOUT_RECOVERY = 0x00000217
    NV_WRITE_RECOVERY = 0x00000218
    AUDIT_COUNTER_0 = 0x00000219
    AUDIT_COUNTER_1 = 0x00000220


@tpm_enum
class TPM_PT_PCR(UINT32):
    SAVE = 0x00000000
    EXTEND_L0 = 0x00000001
    RESET_L0 = 0x00000002
    EXTEND_L1 = 0x00000003
    RESET_L1 = 0x00000004
    EXTEND_L2 = 0x00000005
    RESET_L2 = 0x00000006
    EXTEND_L3 = 0x00000007
    RESET_L3 = 0x00000008
    EXTEND_L4 = 0x00000009
    RESET_L4 = 0x0000000A
    PCR_NO_INCREMENT = 0x00000011
    PCR_DRTM_RESET = 0x00000012
    PCR_POLICY = 0x00000013
    PCR_AUTH = 0x00000014


@tpm_enum
class TPM_PS(UINT32):
    MAIN = 0x00000000
    PC = 0x00000001
    PDA = 0x00000002
    CELL_PHONE = 0x00000003
    SERVER = 0x00000004
    PERIPHERAL = 0x00000005
    TSS = 0x00000006
    STORAGE = 0x00000007
    AUTHENTICATION = 0x00000008
    EMBEDDED = 0x00000009
    HARDCOPY = 0x0000000A
    INFRASTRUCTURE = 0x0000000B
    VIRTUALIZATION = 0x0000000C
    TNC = 0x0000000D
    MULTI_TENANT = 0x0000000E
    TC = 0x0000000F
