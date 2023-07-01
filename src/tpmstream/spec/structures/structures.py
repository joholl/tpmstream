from ..common.values import ValidValues, tpm_dataclass
from .attribute_structures import TPMA_ACT, TPMA_ALGORITHM, TPMA_CC, TPMA_SESSION
from .base_types import BYTE, UINT8, UINT16, UINT32, UINT64
from .constants import (
    TPM_ALG,
    TPM_ALG_ID,
    TPM_CAP,
    TPM_CC,
    TPM_ECC_CURVE,
    TPM_GENERATED,
    TPM_PT,
    TPM_PT_PCR,
    TPM_ST,
)
from .handles import TPM_HANDLE
from .interface_types import (
    TPMI_ALG_HASH,
    TPMI_RH_HIERARCHY,
    TPMI_SH_AUTH_SESSION,
    TPMI_YES_NO,
)


@tpm_dataclass
class TPMS_EMPTY:
    pass


@tpm_dataclass
class TPMS_ALGORITHM_DESCRIPTION:
    alg: TPM_ALG_ID
    attributes: TPMA_ALGORITHM


# TODO can we somehow use TPM_ALG.by_type_exactly(AlgType.Hash) here?
# TODO statically sized list of bytes??
@tpm_dataclass
class TPMU_HA:
    _list_size = {
        "sha": 20,
        "sha1": 20,
        "sha256": 32,
        "sha384": 48,
        "sha512": 64,
        "sm3_256": 32,
        "sha3_256": 32,
        "sha3_384": 48,
        "sha3_512": 64,
    }
    _selected_by = {
        "sha": TPM_ALG.SHA,
        "sha1": TPM_ALG.SHA1,
        "sha256": TPM_ALG.SHA256,
        "sha384": TPM_ALG.SHA384,
        "sha512": TPM_ALG.SHA512,
        "sm3_256": TPM_ALG.SM3_256,
        "sha3_256": TPM_ALG.SHA3_256,
        "sha3_384": TPM_ALG.SHA3_384,
        "sha3_512": TPM_ALG.SHA3_512,
        "null": TPM_ALG.NULL,
    }

    sha: list[BYTE]
    sha1: list[BYTE]
    sha256: list[BYTE]
    sha384: list[BYTE]
    sha512: list[BYTE]
    sm3_256: list[BYTE]
    sha3_256: list[BYTE]
    sha3_384: list[BYTE]
    sha3_512: list[BYTE]
    null: None


@tpm_dataclass
class TPMT_HA:
    _selectors = {
        "digest": "hashAlg",
    }

    hashAlg: TPMI_ALG_HASH.plus()
    digest: TPMU_HA


# TODO some of these types look the same, but the max size of the buffer is different.
#      do we want to add that in the future?


@tpm_dataclass
class TPM2B_DIGEST:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPM2B_DATA:
    size: UINT16
    buffer: list[BYTE]


class TPM2B_NONCE(TPM2B_DIGEST):
    pass


class TPM2B_AUTH(TPM2B_DIGEST):
    pass


class TPM2B_OPERAND(TPM2B_DIGEST):
    pass


@tpm_dataclass
class TPM2B_EVENT:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPM2B_MAX_BUFFER:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPM2B_MAX_NV_BUFFER:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPM2B_TIMEOUT:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPM2B_IV:
    size: UINT16
    buffer: list[BYTE]


@tpm_dataclass
class TPMU_NAME:
    # TODO look up in TSS?
    _selected_by = {
        "digest": 1337,
        "handle": 1337,
    }

    digest: TPMT_HA
    handle: TPM_HANDLE


@tpm_dataclass
class TPM2B_NAME:
    size: UINT16
    name: list[BYTE]


@tpm_dataclass
class TPMS_PCR_SELECT:
    sizeofSelect: UINT8
    pcrSelect: list[BYTE]


@tpm_dataclass
class TPMS_PCR_SELECTION:
    hash: TPMI_ALG_HASH
    sizeofSelect: UINT8
    pcrSelect: list[BYTE]


@tpm_dataclass
class TPMT_TK_CREATION:
    tag: TPM_ST  # TODO TPM_ST_CREATION only?
    hierarchy: TPMI_RH_HIERARCHY.plus()
    digest: TPM2B_DIGEST


@tpm_dataclass
class TPMT_TK_VERIFIED:
    tag: TPM_ST  # TODO TPM_ST_VERIFIED only?
    hierarchy: TPMI_RH_HIERARCHY.plus()
    digest: TPM2B_DIGEST


@tpm_dataclass
class TPMT_TK_AUTH:
    tag: TPM_ST  # TODO TPM_ST_AUTH_SIGNED, TPM_ST_AUTH_SECRET only?
    hierarchy: TPMI_RH_HIERARCHY.plus()
    digest: TPM2B_DIGEST


@tpm_dataclass
class TPMT_TK_HASHCHECK:
    tag: TPM_ST  # TODO TPM_ST_HASHCHECK only?
    hierarchy: TPMI_RH_HIERARCHY.plus()
    digest: TPM2B_DIGEST


@tpm_dataclass
class TPMS_ALG_PROPERTY:
    alg: TPM_ALG_ID
    algProperties: TPMA_ALGORITHM


@tpm_dataclass
class TPMS_TAGGED_PROPERTY:
    property: TPM_PT
    value: UINT32


@tpm_dataclass
class TPMS_TAGGED_PCR_SELECT:
    tag: TPM_PT_PCR
    sizeofSelect: UINT8
    pcrSelect: list[BYTE]


@tpm_dataclass
class TPMS_TAGGED_POLICY:
    handle: TPM_HANDLE
    policyHash: TPMT_HA


@tpm_dataclass
class TPMS_ACT_DATA:
    handle: TPM_HANDLE
    timeout: UINT32
    attributes: TPMA_ACT


@tpm_dataclass
class TPML_CC:
    count: UINT32
    commandCodes: list[TPM_CC]


@tpm_dataclass
class TPML_CCA:
    count: UINT32
    commandAttributes: list[TPMA_CC]


@tpm_dataclass
class TPML_ALG:
    count: UINT32
    algorithms: list[TPM_ALG_ID]


@tpm_dataclass
class TPML_HANDLE:
    count: UINT32
    handle: list[TPM_HANDLE]


@tpm_dataclass
class TPML_DIGEST:
    count: UINT32
    digests: list[TPM2B_DIGEST]


@tpm_dataclass
class TPML_DIGEST_VALUES:
    count: UINT32
    digests: list[TPMT_HA]


@tpm_dataclass
class TPML_PCR_SELECTION:
    count: UINT32
    pcrSelections: list[TPMS_PCR_SELECTION]


@tpm_dataclass
class TPML_ALG_PROPERTY:
    count: UINT32
    algProperties: list[TPMS_ALG_PROPERTY]


@tpm_dataclass
class TPML_TAGGED_TPM_PROPERTY:
    count: UINT32
    tpmProperty: list[TPMS_TAGGED_PROPERTY]


@tpm_dataclass
class TPML_TAGGED_PCR_PROPERTY:
    count: UINT32
    pcrProperty: list[TPMS_TAGGED_PCR_SELECT]


@tpm_dataclass
class TPML_ECC_CURVE:
    count: UINT32
    eccCurves: list[TPM_ECC_CURVE]


@tpm_dataclass
class TPML_TAGGED_POLICY:
    count: UINT32
    policies: list[TPMS_TAGGED_POLICY]


@tpm_dataclass
class TPML_ACT_DATA:
    count: UINT32
    actData: list[TPMS_ACT_DATA]


@tpm_dataclass
class TPMU_CAPABILITIES:
    _selected_by = {
        "algorithms": TPM_CAP.ALGS,
        "handles": TPM_CAP.HANDLES,
        "command": TPM_CAP.COMMANDS,
        "ppCommands": TPM_CAP.PP_COMMANDS,
        "auditCommands": TPM_CAP.AUDIT_COMMANDS,
        "assignedPCR": TPM_CAP.PCRS,
        "tpmProperties": TPM_CAP.TPM_PROPERTIES,
        "pcrProperties": TPM_CAP.PCR_PROPERTIES,
        "eccCurves": TPM_CAP.ECC_CURVES,
        "authPolicies": TPM_CAP.AUTH_POLICIES,
        "actData": TPM_CAP.ACT,
        "null": TPM_CAP.VENDOR_PROPERTY,
    }

    algorithms: TPML_ALG_PROPERTY
    handles: TPML_HANDLE
    command: TPML_CCA
    ppCommands: TPML_CC
    auditCommands: TPML_CC
    assignedPCR: TPML_PCR_SELECTION
    tpmProperties: TPML_TAGGED_TPM_PROPERTY
    pcrProperties: TPML_TAGGED_PCR_PROPERTY
    eccCurves: TPML_ECC_CURVE
    authPolicies: TPML_TAGGED_POLICY
    actData: TPML_ACT_DATA
    null: None  # added to satisfy selector completeness


# TODO union in a non-tagged type
@tpm_dataclass
class TPMS_CAPABILITY_DATA:
    _selectors = {
        "data": "capability",
    }

    capability: TPM_CAP
    data: TPMU_CAPABILITIES


@tpm_dataclass
class TPMS_CLOCK_INFO:
    clock: UINT64
    resetCount: UINT32
    restartCount: UINT32
    safe: TPMI_YES_NO


@tpm_dataclass
class TPMS_TIME_INFO:
    time: UINT64
    clockInfo: TPMS_CLOCK_INFO


@tpm_dataclass
class TPMS_TIME_ATTEST_INFO:
    time: TPMS_TIME_INFO
    firmwareVersion: UINT64


@tpm_dataclass
class TPMS_CERTIFY_INFO:
    name: TPM2B_NAME
    qualifiedName: TPM2B_NAME


@tpm_dataclass
class TPMS_QUOTE_INFO:
    pcrSelect: TPML_PCR_SELECTION
    pcrDigest: TPM2B_DIGEST


@tpm_dataclass
class TPMS_COMMAND_AUDIT_INFO:
    auditCounter: UINT64
    digestAlg: TPM_ALG_ID
    auditDigest: TPM2B_DIGEST
    commandDigest: TPM2B_DIGEST


@tpm_dataclass
class TPMS_SESSION_AUDIT_INFO:
    exclusiveSession: TPMI_YES_NO
    sessionDigest: TPM2B_DIGEST


@tpm_dataclass
class TPMS_CREATION_INFO:
    objectName: TPM2B_NAME
    creationHash: TPM2B_DIGEST


@tpm_dataclass
class TPMS_NV_CERTIFY_INFO:
    indexName: TPM2B_NAME
    offset: UINT16
    nvContents: TPM2B_MAX_NV_BUFFER


@tpm_dataclass
class TPMS_NV_DIGEST_CERTIFY_INFO:
    indexName: TPM2B_NAME
    nvDigest: TPM2B_DIGEST


class TPMI_ST_ATTEST(TPM_ST):
    _valid_values = ValidValues(
        TPM_ST.ATTEST_CERTIFY,
        TPM_ST.ATTEST_QUOTE,
        TPM_ST.ATTEST_SESSION_AUDIT,
        TPM_ST.ATTEST_COMMAND_AUDIT,
        TPM_ST.ATTEST_TIME,
        TPM_ST.ATTEST_CREATION,
        TPM_ST.ATTEST_NV,
        TPM_ST.ATTEST_NV_DIGEST,
    )


@tpm_dataclass
class TPMS_NV_DIGEST_CERTIFY_INFO:
    indexName: TPM2B_NAME
    nvDigest: TPM2B_DIGEST


@tpm_dataclass
class TPMU_ATTEST:
    _selected_by = {
        "certify": TPM_ST.ATTEST_CERTIFY,
        "creation": TPM_ST.ATTEST_CREATION,
        "quote": TPM_ST.ATTEST_QUOTE,
        "commandAudit": TPM_ST.ATTEST_COMMAND_AUDIT,
        "sessionAudit": TPM_ST.ATTEST_SESSION_AUDIT,
        "time": TPM_ST.ATTEST_TIME,
        "nv": TPM_ST.ATTEST_NV,
        "nvDigest": TPM_ST.ATTEST_NV_DIGEST,
    }

    certify: TPMS_CERTIFY_INFO
    creation: TPMS_CREATION_INFO
    quote: TPMS_QUOTE_INFO
    commandAudit: TPMS_COMMAND_AUDIT_INFO
    sessionAudit: TPMS_SESSION_AUDIT_INFO
    time: TPMS_TIME_ATTEST_INFO
    nv: TPMS_NV_CERTIFY_INFO
    nvDigest: TPMS_NV_DIGEST_CERTIFY_INFO


@tpm_dataclass
class TPMS_ATTEST:
    _selectors = {
        "attested": "type",
    }

    magic: TPM_GENERATED
    type: TPMI_ST_ATTEST
    qualifiedSigner: TPM2B_NAME
    extraData: TPM2B_DATA
    clockInfo: TPMS_CLOCK_INFO
    firmwareVersion: UINT64
    attested: TPMU_ATTEST


@tpm_dataclass
class TPM2B_ATTEST:
    size: UINT16
    attestationData: list[BYTE]


@tpm_dataclass
class TPMS_AUTH_COMMAND:
    sessionHandle: TPMI_SH_AUTH_SESSION.plus()
    nonce: TPM2B_NONCE
    sessionAttributes: TPMA_SESSION
    hmac: TPM2B_AUTH


@tpm_dataclass
class TPMS_AUTH_RESPONSE:
    nonce: TPM2B_NONCE
    sessionAttributes: TPMA_SESSION
    hmac: TPM2B_AUTH


@tpm_dataclass
class TPMS_AUTH_RESPONSE:
    nonce: TPM2B_NONCE
    sessionAttributes: TPMA_SESSION
    hmac: TPM2B_AUTH
