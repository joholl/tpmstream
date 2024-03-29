from ..common.values import tpm_dataclass
from ..structures.algorithm_parameters_and_structures import (
    TPM2B_ECC_PARAMETER,
    TPM2B_ECC_POINT,
    TPM2B_ENCRYPTED_SECRET,
    TPM2B_PUBLIC_KEY_RSA,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_SENSITIVE_DATA,
    TPMI_ECC_CURVE,
    TPMT_RSA_DECRYPT,
    TPMT_SIG_SCHEME,
    TPMT_SIGNATURE,
    TPMT_SYM_DEF,
    TPMT_SYM_DEF_OBJECT,
)
from ..structures.attached_component_structures import TPM_AT
from ..structures.attribute_structures import TPMA_LOCALITY
from ..structures.base_types import INT32, UINT16, UINT32, UINT64
from ..structures.constants import (
    TPM_CAP,
    TPM_CC,
    TPM_CLOCK_ADJUST,
    TPM_EO,
    TPM_SE,
    TPM_SU,
)
from ..structures.context_data import TPMS_CONTEXT
from ..structures.interface_types import (
    TPMI_ALG_CIPHER_MODE,
    TPMI_ALG_HASH,
    TPMI_DH_PCR,
    TPMI_DH_PERSISTENT,
    TPMI_ECC_KEY_EXCHANGE,
    TPMI_RH_ENABLES,
    TPMI_RH_HIERARCHY,
    TPMI_YES_NO,
)
from ..structures.key_object_complex import (
    TPM2B_ID_OBJECT,
    TPM2B_PRIVATE,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE,
    TPM2B_TEMPLATE,
    TPMT_PUBLIC_PARMS,
)
from ..structures.nv_storage_structures import TPM2B_NV_PUBLIC
from ..structures.structures import (
    TPM2B_AUTH,
    TPM2B_DATA,
    TPM2B_DIGEST,
    TPM2B_EVENT,
    TPM2B_IV,
    TPM2B_MAX_BUFFER,
    TPM2B_MAX_NV_BUFFER,
    TPM2B_NAME,
    TPM2B_NONCE,
    TPM2B_OPERAND,
    TPM2B_TIMEOUT,
    TPML_ALG,
    TPML_CC,
    TPML_DIGEST,
    TPML_DIGEST_VALUES,
    TPML_PCR_SELECTION,
    TPMT_TK_AUTH,
    TPMT_TK_CREATION,
    TPMT_TK_HASHCHECK,
    TPMT_TK_VERIFIED,
)
from .params_common import TPMS_PARAMS

# TODO TPM2_MAC Command
# TODO TPM2_MAC_Start Command


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_UNDEFINE_SPACE_SPECIAL(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_EVICT_CONTROL(TPMS_PARAMS):
    persistentHandle: TPMI_DH_PERSISTENT


@tpm_dataclass
class TPMS_COMMAND_PARAMS_HIERARCHY_CONTROL(TPMS_PARAMS):
    enable: TPMI_RH_ENABLES
    state: TPMI_YES_NO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_UNDEFINE_SPACE(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CHANGE_EPS(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CHANGE_PPS(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CLEAR(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CLEAR_CONTROL(TPMS_PARAMS):
    disable: TPMI_YES_NO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CLOCK_SET(TPMS_PARAMS):
    newTime: UINT64


@tpm_dataclass
class TPMS_COMMAND_PARAMS_HIERARCHY_CHANGE_AUTH(TPMS_PARAMS):
    newAuth: TPM2B_AUTH


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_DEFINE_SPACE(TPMS_PARAMS):
    auth: TPM2B_AUTH
    publicInfo: TPM2B_NV_PUBLIC


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PCR_ALLOCATE(TPMS_PARAMS):
    pcrAllocation: TPML_PCR_SELECTION


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PCR_SET_AUTH_POLICY(TPMS_PARAMS):
    authPolicy: TPM2B_DIGEST
    hashAlg: TPMI_ALG_HASH
    pcrNum: TPMI_DH_PCR


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PP_COMMANDS(TPMS_PARAMS):
    setList: TPML_CC
    clearList: TPML_CC


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SET_PRIMARY_POLICY(TPMS_PARAMS):
    authPolicy: TPM2B_DIGEST
    hashAlg: TPMI_ALG_HASH


@tpm_dataclass
class TPMS_COMMAND_PARAMS_FIELD_UPGRADE_START(TPMS_PARAMS):
    fuDigest: TPM2B_DIGEST
    manifestSignature: TPMT_SIGNATURE


@tpm_dataclass
class TPMS_COMMAND_PARAMS_INCREMENTAL_SELF_TEST(TPMS_PARAMS):
    toTest: TPML_ALG


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SELF_TEST(TPMS_PARAMS):
    fullTest: TPMI_YES_NO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_STARTUP(TPMS_PARAMS):
    startupType: TPM_SU


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SHUTDOWN(TPMS_PARAMS):
    shutdownType: TPM_SU


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CLOCK_RATE_ADJUST(TPMS_PARAMS):
    rateAdjust: TPM_CLOCK_ADJUST


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CREATE_PRIMARY(TPMS_PARAMS):
    inSensitive: TPM2B_SENSITIVE_CREATE
    inPublic: TPM2B_PUBLIC
    outsideInfo: TPM2B_DATA
    creationPCR: TPML_PCR_SELECTION


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_GLOBAL_WRITE_LOCK(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_GET_COMMAND_AUDIT_DIGEST(TPMS_PARAMS):
    qualifyingData: TPM2B_DATA
    inScheme: TPMT_SIG_SCHEME


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_INCREMENT(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_SET_BITS(TPMS_PARAMS):
    bits: UINT64


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_EXTEND(TPMS_PARAMS):
    data: TPM2B_MAX_NV_BUFFER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_WRITE(TPMS_PARAMS):
    data: TPM2B_MAX_NV_BUFFER
    offset: UINT16


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_WRITE_LOCK(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_DICTIONARY_ATTACK_LOCK_RESET(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_DICTIONARY_ATTACK_PARAMETERS(TPMS_PARAMS):
    newMaxTries: UINT32
    newRecoveryTime: UINT32
    lockoutRecovery: UINT32


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_CHANGE_AUTH(TPMS_PARAMS):
    newAuth: TPM2B_AUTH


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PCR_EVENT(TPMS_PARAMS):
    eventData: TPM2B_EVENT


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PCR_RESET(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SEQUENCE_COMPLETE(TPMS_PARAMS):
    buffer: TPM2B_MAX_BUFFER
    hierarchy: TPMI_RH_HIERARCHY


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SET_ALGORITHM_SET(TPMS_PARAMS):
    algorithmSet: UINT32


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SET_COMMAND_CODE_AUDIT_STATUS(TPMS_PARAMS):
    auditAlg: TPMI_ALG_HASH
    setList: TPML_CC
    clearList: TPML_CC


@tpm_dataclass
class TPMS_COMMAND_PARAMS_FIELD_UPGRADE_DATA(TPMS_PARAMS):
    fuData: TPM2B_MAX_BUFFER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_STIR_RANDOM(TPMS_PARAMS):
    inData: TPM2B_SENSITIVE_DATA


@tpm_dataclass
class TPMS_COMMAND_PARAMS_ACTIVATE_CREDENTIAL(TPMS_PARAMS):
    credentialBlob: TPM2B_ID_OBJECT
    secret: TPM2B_ENCRYPTED_SECRET


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CERTIFY(TPMS_PARAMS):
    qualifyingData: TPM2B_DATA
    inScheme: TPMT_SIG_SCHEME


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_NV(TPMS_PARAMS):
    operandB: TPM2B_OPERAND
    offset: UINT16
    operation: TPM_EO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CERTIFY_CREATION(TPMS_PARAMS):
    qualifyingData: TPM2B_DATA
    creationHash: TPM2B_DIGEST
    inScheme: TPMT_SIG_SCHEME
    creationTicket: TPMT_TK_CREATION


@tpm_dataclass
class TPMS_COMMAND_PARAMS_DUPLICATE(TPMS_PARAMS):
    encryptionKeyIn: TPM2B_DATA
    symmetricAlg: TPMT_SYM_DEF_OBJECT.plus()


@tpm_dataclass
class TPMS_COMMAND_PARAMS_GET_TIME(TPMS_PARAMS):
    qualifyingData: TPM2B_DATA
    inScheme: TPMT_SIG_SCHEME


@tpm_dataclass
class TPMS_COMMAND_PARAMS_GET_SESSION_AUDIT_DIGEST(TPMS_PARAMS):
    qualifyingData: TPM2B_DATA
    inScheme: TPMT_SIG_SCHEME


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_READ(TPMS_PARAMS):
    size: UINT16
    offset: UINT16


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_READ_LOCK(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_OBJECT_CHANGE_AUTH(TPMS_PARAMS):
    newAuth: TPM2B_AUTH


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_SECRET(TPMS_PARAMS):
    nonceTPM: TPM2B_NONCE
    cpHashA: TPM2B_DIGEST
    policyRef: TPM2B_NONCE
    expiration: INT32


@tpm_dataclass
class TPMS_COMMAND_PARAMS_REWRAP(TPMS_PARAMS):
    inDuplicate: TPM2B_PRIVATE
    name: TPM2B_NAME
    inSymSeed: TPM2B_ENCRYPTED_SECRET


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CREATE(TPMS_PARAMS):
    inSensitive: TPM2B_SENSITIVE_CREATE
    inPublic: TPM2B_PUBLIC
    outsideInfo: TPM2B_DATA
    creationPCR: TPML_PCR_SELECTION


@tpm_dataclass
class TPMS_COMMAND_PARAMS_ECDH_Z_GEN(TPMS_PARAMS):
    inPoint: TPM2B_ECC_POINT


@tpm_dataclass
class TPMS_COMMAND_PARAMS_HMAC(TPMS_PARAMS):
    buffer: TPM2B_MAX_BUFFER
    hashAlg: TPMI_ALG_HASH.plus()


@tpm_dataclass
class TPMS_COMMAND_PARAMS_IMPORT(TPMS_PARAMS):
    encryptionKey: TPM2B_DATA
    objectPublic: TPM2B_PUBLIC
    duplicate: TPM2B_PRIVATE
    inSymSeed: TPM2B_ENCRYPTED_SECRET
    symmetricAlg: TPMT_SYM_DEF_OBJECT.plus()


@tpm_dataclass
class TPMS_COMMAND_PARAMS_LOAD(TPMS_PARAMS):
    inPrivate: TPM2B_PRIVATE
    inPublic: TPM2B_PUBLIC


@tpm_dataclass
class TPMS_COMMAND_PARAMS_QUOTE(TPMS_PARAMS):
    qualifyingData: TPM2B_DATA
    inScheme: TPMT_SIG_SCHEME
    PCRselect: TPML_PCR_SELECTION


@tpm_dataclass
class TPMS_COMMAND_PARAMS_RSA_DECRYPT(TPMS_PARAMS):
    cipherText: TPM2B_PUBLIC_KEY_RSA
    inScheme: TPMT_RSA_DECRYPT.plus()
    label: TPM2B_DATA


@tpm_dataclass
class TPMS_COMMAND_PARAMS_HMAC_START(TPMS_PARAMS):
    auth: TPM2B_AUTH
    hashAlg: TPMI_ALG_HASH.plus()


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SEQUENCE_UPDATE(TPMS_PARAMS):
    buffer: TPM2B_MAX_BUFFER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_SIGN(TPMS_PARAMS):
    digest: TPM2B_DIGEST
    inScheme: TPMT_SIG_SCHEME
    validation: TPMT_TK_HASHCHECK


@tpm_dataclass
class TPMS_COMMAND_PARAMS_UNSEAL(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_SIGNED(TPMS_PARAMS):
    nonceTPM: TPM2B_NONCE
    cpHashA: TPM2B_DIGEST
    policyRef: TPM2B_NONCE
    expiration: INT32
    auth: TPMT_SIGNATURE


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CONTEXT_LOAD(TPMS_PARAMS):
    context: TPMS_CONTEXT


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CONTEXT_SAVE(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_ECDH_KEY_GEN(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_ENCRYPT_DECRYPT(TPMS_PARAMS):
    decrypt: TPMI_YES_NO
    mode: TPMI_ALG_CIPHER_MODE.plus()
    ivIn: TPM2B_IV
    inData: TPM2B_MAX_BUFFER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_FLUSH_CONTEXT(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_LOAD_EXTERNAL(TPMS_PARAMS):
    inPrivate: TPM2B_SENSITIVE
    inPublic: TPM2B_PUBLIC.plus()
    hierarchy: TPMI_RH_HIERARCHY.plus()


@tpm_dataclass
class TPMS_COMMAND_PARAMS_MAKE_CREDENTIAL(TPMS_PARAMS):
    credential: TPM2B_DIGEST
    objectName: TPM2B_NAME


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_READ_PUBLIC(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_AUTHORIZE(TPMS_PARAMS):
    approvedPolicy: TPM2B_DIGEST
    policyRef: TPM2B_NONCE
    keySign: TPM2B_NAME
    checkTicket: TPMT_TK_VERIFIED


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_AUTH_VALUE(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_COMMAND_CODE(TPMS_PARAMS):
    code: TPM_CC


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_COUNTER_TIMER(TPMS_PARAMS):
    operandB: TPM2B_OPERAND
    offset: UINT16
    operation: TPM_EO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_CP_HASH(TPMS_PARAMS):
    cpHashA: TPM2B_DIGEST


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_LOCALITY(TPMS_PARAMS):
    locality: TPMA_LOCALITY


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_NAME_HASH(TPMS_PARAMS):
    nameHash: TPM2B_DIGEST


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_OR(TPMS_PARAMS):
    pHashList: TPML_DIGEST


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_TICKET(TPMS_PARAMS):
    timeout: TPM2B_TIMEOUT
    cpHashA: TPM2B_DIGEST
    policyRef: TPM2B_NONCE
    authName: TPM2B_NAME
    ticket: TPMT_TK_AUTH


@tpm_dataclass
class TPMS_COMMAND_PARAMS_READ_PUBLIC(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_RSA_ENCRYPT(TPMS_PARAMS):
    message: TPM2B_PUBLIC_KEY_RSA
    inScheme: TPMT_RSA_DECRYPT.plus()
    label: TPM2B_DATA


@tpm_dataclass
class TPMS_COMMAND_PARAMS_START_AUTH_SESSION(TPMS_PARAMS):
    nonceCaller: TPM2B_NONCE
    encryptedSalt: TPM2B_ENCRYPTED_SECRET
    sessionType: TPM_SE
    symmetric: TPMT_SYM_DEF.plus()
    authHash: TPMI_ALG_HASH


@tpm_dataclass
class TPMS_COMMAND_PARAMS_VERIFY_SIGNATURE(TPMS_PARAMS):
    digest: TPM2B_DIGEST
    signature: TPMT_SIGNATURE


@tpm_dataclass
class TPMS_COMMAND_PARAMS_ECC_PARAMETERS(TPMS_PARAMS):
    curveID: TPMI_ECC_CURVE


@tpm_dataclass
class TPMS_COMMAND_PARAMS_FIRMWARE_READ(TPMS_PARAMS):
    sequenceNumber: UINT32


@tpm_dataclass
class TPMS_COMMAND_PARAMS_GET_CAPABILITY(TPMS_PARAMS):
    capability: TPM_CAP
    property: UINT32
    propertyCount: UINT32


@tpm_dataclass
class TPMS_COMMAND_PARAMS_GET_RANDOM(TPMS_PARAMS):
    bytesRequested: UINT16


@tpm_dataclass
class TPMS_COMMAND_PARAMS_GET_TEST_RESULT(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_HASH(TPMS_PARAMS):
    data: TPM2B_MAX_BUFFER
    hashAlg: TPMI_ALG_HASH
    hierarchy: TPMI_RH_HIERARCHY


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PCR_READ(TPMS_PARAMS):
    pcrSelectionIn: TPML_PCR_SELECTION


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_PCR(TPMS_PARAMS):
    pcrDigest: TPM2B_DIGEST
    pcrs: TPML_PCR_SELECTION


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_RESTART(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_READ_CLOCK(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PCR_EXTEND(TPMS_PARAMS):
    digests: TPML_DIGEST_VALUES


@tpm_dataclass
class TPMS_COMMAND_PARAMS_PCR_SET_AUTH_VALUE(TPMS_PARAMS):
    auth: TPM2B_DIGEST


@tpm_dataclass
class TPMS_COMMAND_PARAMS_NV_CERTIFY(TPMS_PARAMS):
    qualifyingData: TPM2B_DATA
    inScheme: TPMT_SIG_SCHEME
    size: UINT16
    offset: UINT16


@tpm_dataclass
class TPMS_COMMAND_PARAMS_EVENT_SEQUENCE_COMPLETE(TPMS_PARAMS):
    buffer: TPM2B_MAX_BUFFER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_HASH_SEQUENCE_START(TPMS_PARAMS):
    auth: TPM2B_AUTH
    hashAlg: TPMI_ALG_HASH


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_PHYSICAL_PRESENCE(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_DUPLICATION_SELECT(TPMS_PARAMS):
    objectName: TPM2B_NAME
    newParentName: TPM2B_NAME
    includeObject: TPMI_YES_NO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_GET_DIGEST(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_TEST_PARMS(TPMS_PARAMS):
    parameters: TPMT_PUBLIC_PARMS


@tpm_dataclass
class TPMS_COMMAND_PARAMS_COMMIT(TPMS_PARAMS):
    P1: TPM2B_ECC_POINT
    s2: TPM2B_SENSITIVE_DATA
    y2: TPM2B_ECC_PARAMETER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_PASSWORD(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_Z_GEN_2_PHASE(TPMS_PARAMS):
    inQsB: TPM2B_ECC_POINT
    inQeB: TPM2B_ECC_POINT
    inScheme: TPMI_ECC_KEY_EXCHANGE
    counter: UINT16


@tpm_dataclass
class TPMS_COMMAND_PARAMS_EC_EPHEMERAL(TPMS_PARAMS):
    curveID: TPMI_ECC_CURVE


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_NV_WRITTEN(TPMS_PARAMS):
    writtenSet: TPMI_YES_NO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_TEMPLATE(TPMS_PARAMS):
    templateHash: TPM2B_DIGEST


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CREATE_LOADED(TPMS_PARAMS):
    inSensitive: TPM2B_SENSITIVE_CREATE
    inPublic: TPM2B_TEMPLATE


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_AUTHORIZE_NV(TPMS_PARAMS):
    pass


@tpm_dataclass
class TPMS_COMMAND_PARAMS_ENCRYPT_DECRYPT2(TPMS_PARAMS):
    inData: TPM2B_MAX_BUFFER
    decrypt: TPMI_YES_NO
    mode: TPMI_ALG_CIPHER_MODE.plus()
    ivIn: TPM2B_IV


@tpm_dataclass
class TPMS_COMMAND_PARAMS_AC_GET_CAPABILITY(TPMS_PARAMS):
    capability: TPM_AT
    count: UINT32


@tpm_dataclass
class TPMS_COMMAND_PARAMS_AC_SEND(TPMS_PARAMS):
    acDataIn: TPM2B_MAX_BUFFER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_POLICY_AC_SEND_SELECT(TPMS_PARAMS):
    objectName: TPM2B_NAME
    authHandleName: TPM2B_NAME
    acName: TPM2B_NAME
    includeObject: TPMI_YES_NO


@tpm_dataclass
class TPMS_COMMAND_PARAMS_CERTIFY_X509(TPMS_PARAMS):
    reserved: TPM2B_DATA
    inScheme: TPMT_SIG_SCHEME
    partialCertificate: TPM2B_MAX_BUFFER


@tpm_dataclass
class TPMS_COMMAND_PARAMS_ACT_SET_TIMEOUT(TPMS_PARAMS):
    startTimeout: UINT32


command_param_types = {
    TPM_CC.NV_UndefineSpaceSpecial: TPMS_COMMAND_PARAMS_NV_UNDEFINE_SPACE_SPECIAL,
    TPM_CC.EvictControl: TPMS_COMMAND_PARAMS_EVICT_CONTROL,
    TPM_CC.HierarchyControl: TPMS_COMMAND_PARAMS_HIERARCHY_CONTROL,
    TPM_CC.NV_UndefineSpace: TPMS_COMMAND_PARAMS_NV_UNDEFINE_SPACE,
    TPM_CC.ChangeEPS: TPMS_COMMAND_PARAMS_CHANGE_EPS,
    TPM_CC.ChangePPS: TPMS_COMMAND_PARAMS_CHANGE_PPS,
    TPM_CC.Clear: TPMS_COMMAND_PARAMS_CLEAR,
    TPM_CC.ClearControl: TPMS_COMMAND_PARAMS_CLEAR_CONTROL,
    TPM_CC.ClockSet: TPMS_COMMAND_PARAMS_CLOCK_SET,
    TPM_CC.HierarchyChangeAuth: TPMS_COMMAND_PARAMS_HIERARCHY_CHANGE_AUTH,
    TPM_CC.NV_DefineSpace: TPMS_COMMAND_PARAMS_NV_DEFINE_SPACE,
    TPM_CC.PCR_Allocate: TPMS_COMMAND_PARAMS_PCR_ALLOCATE,
    TPM_CC.PCR_SetAuthPolicy: TPMS_COMMAND_PARAMS_PCR_SET_AUTH_POLICY,
    TPM_CC.PP_Commands: TPMS_COMMAND_PARAMS_PP_COMMANDS,
    TPM_CC.SetPrimaryPolicy: TPMS_COMMAND_PARAMS_SET_PRIMARY_POLICY,
    TPM_CC.FieldUpgradeStart: TPMS_COMMAND_PARAMS_FIELD_UPGRADE_START,
    TPM_CC.ClockRateAdjust: TPMS_COMMAND_PARAMS_CLOCK_RATE_ADJUST,
    TPM_CC.CreatePrimary: TPMS_COMMAND_PARAMS_CREATE_PRIMARY,
    TPM_CC.NV_GlobalWriteLock: TPMS_COMMAND_PARAMS_NV_GLOBAL_WRITE_LOCK,
    TPM_CC.GetCommandAuditDigest: TPMS_COMMAND_PARAMS_GET_COMMAND_AUDIT_DIGEST,
    TPM_CC.NV_Increment: TPMS_COMMAND_PARAMS_NV_INCREMENT,
    TPM_CC.NV_SetBits: TPMS_COMMAND_PARAMS_NV_SET_BITS,
    TPM_CC.NV_Extend: TPMS_COMMAND_PARAMS_NV_EXTEND,
    TPM_CC.NV_Write: TPMS_COMMAND_PARAMS_NV_WRITE,
    TPM_CC.NV_WriteLock: TPMS_COMMAND_PARAMS_NV_WRITE_LOCK,
    TPM_CC.DictionaryAttackLockReset: TPMS_COMMAND_PARAMS_DICTIONARY_ATTACK_LOCK_RESET,
    TPM_CC.DictionaryAttackParameters: TPMS_COMMAND_PARAMS_DICTIONARY_ATTACK_PARAMETERS,
    TPM_CC.NV_ChangeAuth: TPMS_COMMAND_PARAMS_NV_CHANGE_AUTH,
    TPM_CC.PCR_Event: TPMS_COMMAND_PARAMS_PCR_EVENT,
    TPM_CC.PCR_Reset: TPMS_COMMAND_PARAMS_PCR_RESET,
    TPM_CC.SequenceComplete: TPMS_COMMAND_PARAMS_SEQUENCE_COMPLETE,
    TPM_CC.SetAlgorithmSet: TPMS_COMMAND_PARAMS_SET_ALGORITHM_SET,
    TPM_CC.SetCommandCodeAuditStatus: TPMS_COMMAND_PARAMS_SET_COMMAND_CODE_AUDIT_STATUS,
    TPM_CC.FieldUpgradeData: TPMS_COMMAND_PARAMS_FIELD_UPGRADE_DATA,
    TPM_CC.IncrementalSelfTest: TPMS_COMMAND_PARAMS_INCREMENTAL_SELF_TEST,
    TPM_CC.SelfTest: TPMS_COMMAND_PARAMS_SELF_TEST,
    TPM_CC.Startup: TPMS_COMMAND_PARAMS_STARTUP,
    TPM_CC.Shutdown: TPMS_COMMAND_PARAMS_SHUTDOWN,
    TPM_CC.StirRandom: TPMS_COMMAND_PARAMS_STIR_RANDOM,
    TPM_CC.ActivateCredential: TPMS_COMMAND_PARAMS_ACTIVATE_CREDENTIAL,
    TPM_CC.Certify: TPMS_COMMAND_PARAMS_CERTIFY,
    TPM_CC.PolicyNV: TPMS_COMMAND_PARAMS_POLICY_NV,
    TPM_CC.CertifyCreation: TPMS_COMMAND_PARAMS_CERTIFY_CREATION,
    TPM_CC.Duplicate: TPMS_COMMAND_PARAMS_DUPLICATE,
    TPM_CC.GetTime: TPMS_COMMAND_PARAMS_GET_TIME,
    TPM_CC.GetSessionAuditDigest: TPMS_COMMAND_PARAMS_GET_SESSION_AUDIT_DIGEST,
    TPM_CC.NV_Read: TPMS_COMMAND_PARAMS_NV_READ,
    TPM_CC.NV_ReadLock: TPMS_COMMAND_PARAMS_NV_READ_LOCK,
    TPM_CC.ObjectChangeAuth: TPMS_COMMAND_PARAMS_OBJECT_CHANGE_AUTH,
    TPM_CC.PolicySecret: TPMS_COMMAND_PARAMS_POLICY_SECRET,
    TPM_CC.Rewrap: TPMS_COMMAND_PARAMS_REWRAP,
    TPM_CC.Create: TPMS_COMMAND_PARAMS_CREATE,
    TPM_CC.ECDH_ZGen: TPMS_COMMAND_PARAMS_ECDH_Z_GEN,
    TPM_CC.HMAC: TPMS_COMMAND_PARAMS_HMAC,
    TPM_CC.Import: TPMS_COMMAND_PARAMS_IMPORT,
    TPM_CC.Load: TPMS_COMMAND_PARAMS_LOAD,
    TPM_CC.Quote: TPMS_COMMAND_PARAMS_QUOTE,
    TPM_CC.RSA_Decrypt: TPMS_COMMAND_PARAMS_RSA_DECRYPT,
    TPM_CC.HMAC_Start: TPMS_COMMAND_PARAMS_HMAC_START,
    TPM_CC.SequenceUpdate: TPMS_COMMAND_PARAMS_SEQUENCE_UPDATE,
    TPM_CC.Sign: TPMS_COMMAND_PARAMS_SIGN,
    TPM_CC.Unseal: TPMS_COMMAND_PARAMS_UNSEAL,
    TPM_CC.PolicySigned: TPMS_COMMAND_PARAMS_POLICY_SIGNED,
    TPM_CC.ContextLoad: TPMS_COMMAND_PARAMS_CONTEXT_LOAD,
    TPM_CC.ContextSave: TPMS_COMMAND_PARAMS_CONTEXT_SAVE,
    TPM_CC.ECDH_KeyGen: TPMS_COMMAND_PARAMS_ECDH_KEY_GEN,
    TPM_CC.EncryptDecrypt: TPMS_COMMAND_PARAMS_ENCRYPT_DECRYPT,
    TPM_CC.FlushContext: TPMS_COMMAND_PARAMS_FLUSH_CONTEXT,
    TPM_CC.LoadExternal: TPMS_COMMAND_PARAMS_LOAD_EXTERNAL,
    TPM_CC.MakeCredential: TPMS_COMMAND_PARAMS_MAKE_CREDENTIAL,
    TPM_CC.NV_ReadPublic: TPMS_COMMAND_PARAMS_NV_READ_PUBLIC,
    TPM_CC.PolicyAuthorize: TPMS_COMMAND_PARAMS_POLICY_AUTHORIZE,
    TPM_CC.PolicyAuthValue: TPMS_COMMAND_PARAMS_POLICY_AUTH_VALUE,
    TPM_CC.PolicyCommandCode: TPMS_COMMAND_PARAMS_POLICY_COMMAND_CODE,
    TPM_CC.PolicyCounterTimer: TPMS_COMMAND_PARAMS_POLICY_COUNTER_TIMER,
    TPM_CC.PolicyCpHash: TPMS_COMMAND_PARAMS_POLICY_CP_HASH,
    TPM_CC.PolicyLocality: TPMS_COMMAND_PARAMS_POLICY_LOCALITY,
    TPM_CC.PolicyNameHash: TPMS_COMMAND_PARAMS_POLICY_NAME_HASH,
    TPM_CC.PolicyOR: TPMS_COMMAND_PARAMS_POLICY_OR,
    TPM_CC.PolicyTicket: TPMS_COMMAND_PARAMS_POLICY_TICKET,
    TPM_CC.ReadPublic: TPMS_COMMAND_PARAMS_READ_PUBLIC,
    TPM_CC.RSA_Encrypt: TPMS_COMMAND_PARAMS_RSA_ENCRYPT,
    TPM_CC.StartAuthSession: TPMS_COMMAND_PARAMS_START_AUTH_SESSION,
    TPM_CC.VerifySignature: TPMS_COMMAND_PARAMS_VERIFY_SIGNATURE,
    TPM_CC.ECC_Parameters: TPMS_COMMAND_PARAMS_ECC_PARAMETERS,
    TPM_CC.FirmwareRead: TPMS_COMMAND_PARAMS_FIRMWARE_READ,
    TPM_CC.GetCapability: TPMS_COMMAND_PARAMS_GET_CAPABILITY,
    TPM_CC.GetRandom: TPMS_COMMAND_PARAMS_GET_RANDOM,
    TPM_CC.GetTestResult: TPMS_COMMAND_PARAMS_GET_TEST_RESULT,
    TPM_CC.Hash: TPMS_COMMAND_PARAMS_HASH,
    TPM_CC.PCR_Read: TPMS_COMMAND_PARAMS_PCR_READ,
    TPM_CC.PolicyPCR: TPMS_COMMAND_PARAMS_POLICY_PCR,
    TPM_CC.PolicyRestart: TPMS_COMMAND_PARAMS_POLICY_RESTART,
    TPM_CC.ReadClock: TPMS_COMMAND_PARAMS_READ_CLOCK,
    TPM_CC.PCR_Extend: TPMS_COMMAND_PARAMS_PCR_EXTEND,
    TPM_CC.PCR_SetAuthValue: TPMS_COMMAND_PARAMS_PCR_SET_AUTH_VALUE,
    TPM_CC.NV_Certify: TPMS_COMMAND_PARAMS_NV_CERTIFY,
    TPM_CC.EventSequenceComplete: TPMS_COMMAND_PARAMS_EVENT_SEQUENCE_COMPLETE,
    TPM_CC.HashSequenceStart: TPMS_COMMAND_PARAMS_HASH_SEQUENCE_START,
    TPM_CC.PolicyPhysicalPresence: TPMS_COMMAND_PARAMS_POLICY_PHYSICAL_PRESENCE,
    TPM_CC.PolicyDuplicationSelect: TPMS_COMMAND_PARAMS_POLICY_DUPLICATION_SELECT,
    TPM_CC.PolicyGetDigest: TPMS_COMMAND_PARAMS_POLICY_GET_DIGEST,
    TPM_CC.TestParms: TPMS_COMMAND_PARAMS_TEST_PARMS,
    TPM_CC.Commit: TPMS_COMMAND_PARAMS_COMMIT,
    TPM_CC.PolicyPassword: TPMS_COMMAND_PARAMS_POLICY_PASSWORD,
    TPM_CC.ZGen_2Phase: TPMS_COMMAND_PARAMS_Z_GEN_2_PHASE,
    TPM_CC.EC_Ephemeral: TPMS_COMMAND_PARAMS_EC_EPHEMERAL,
    TPM_CC.PolicyNvWritten: TPMS_COMMAND_PARAMS_POLICY_NV_WRITTEN,
    TPM_CC.PolicyTemplate: TPMS_COMMAND_PARAMS_POLICY_TEMPLATE,
    TPM_CC.CreateLoaded: TPMS_COMMAND_PARAMS_CREATE_LOADED,
    TPM_CC.PolicyAuthorizeNV: TPMS_COMMAND_PARAMS_POLICY_AUTHORIZE_NV,
    TPM_CC.EncryptDecrypt2: TPMS_COMMAND_PARAMS_ENCRYPT_DECRYPT2,
    TPM_CC.AC_GetCapability: TPMS_COMMAND_PARAMS_AC_GET_CAPABILITY,
    TPM_CC.AC_Send: TPMS_COMMAND_PARAMS_AC_SEND,
    TPM_CC.Policy_AC_SendSelect: TPMS_COMMAND_PARAMS_POLICY_AC_SEND_SELECT,
    TPM_CC.CertifyX509: TPMS_COMMAND_PARAMS_CERTIFY_X509,
    TPM_CC.ACT_SetTimeout: TPMS_COMMAND_PARAMS_ACT_SET_TIMEOUT,
}
