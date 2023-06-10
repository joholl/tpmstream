from ..common.values import tpm_bitfield
from .base_types import UINT8, UINT32


@tpm_bitfield()
class TPMA_ALGORITHM(UINT32):
    asymmetric = 0x00000001
    symmetric = 0x00000002
    hash = 0x00000004
    object = 0x00000008
    reserved0 = 0x000000F0
    signing = 0x00000100
    encrypt = 0x00000200
    method = 0x00000400
    reserved1 = 0xFFFFF800


@tpm_bitfield()
class TPMA_OBJECT(UINT32):
    reserved = 0x00000001
    fixedTPM = 0x00000002
    stClear = 0x00000004
    reserved0 = 0x00000008
    fixedParent = 0x00000010
    sensitiveDataOrigin = 0x00000020
    userWithAuth = 0x00000040
    adminWithPolicy = 0x00000080
    reserved1 = 0x00000300
    noDA = 0x00000400
    encryptedDuplication = 0x00000800
    reserved2 = 0x0000F000
    restricted = 0x00010000
    decrypt = 0x00020000
    sign_decrypt = 0x00040000
    sign = 0x00080000
    reserved3 = 0xFFF00000


@tpm_bitfield()
class TPMA_SESSION(UINT8):
    continueSession = 0x01
    auditExclusive = 0x02
    auditReset = 0x04
    reserved = 0x18
    decrypt = 0x20
    encrypt = 0x40
    audit = 0x80


@tpm_bitfield()
class TPMA_LOCALITY(UINT8):
    TPM_LOC_ZERO = 0x01
    TPM_LOC_ONE = 0x02
    TPM_LOC_TWO = 0x04
    TPM_LOC_THREE = 0x08
    TPM_LOC_FOUR = 0x10
    extended = 0x60


@tpm_bitfield()
class TPMA_PERMANENT(UINT32):
    ownerAuthSet = 0x00000001
    endorsementAuthSet = 0x00000002
    lockoutAuthSet = 0x00000004
    reserved0 = 0x000000F8
    disableClear = 0x00000100
    inLockout = 0x00000200
    tpmGeneratedEPS = 0x00000400
    reserved1 = 0xFFFFF800


@tpm_bitfield()
class TPMA_STARTUP_CLEAR(UINT32):
    phEnable = 0x00000001
    shEnable = 0x00000002
    ehEnable = 0x00000004
    phEnableNV = 0x00000008
    reserved = 0x7FFFFFF0
    orderly = 0x80000000


@tpm_bitfield()
class TPMA_MEMORY(UINT32):
    sharedRAM = 0x00000001
    sharedNV = 0x00000002
    objectCopiedToRam = 0x00000004
    reserved = 0xFFFFFFF8


@tpm_bitfield()
class TPMA_CC(UINT32):
    commandIndex = 0x0000FFFF
    reserved0 = 0x003F0000
    nv = 0x00400000
    extensive = 0x00800000
    flushed = 0x01000000
    cHandles = 0x0E000000
    rHandle = 0x10000000
    V = 0x20000000
    reserved1 = 0xC0000000


@tpm_bitfield()
class TPMA_MODES(UINT32):
    FIPS_140_2 = 0x00000001
    reserved = 0xFFFFFFFE


@tpm_bitfield()
class TPMA_X509_KEY_USAGE(UINT32):
    reserved = 0x007FFFFF
    decipherOnly = 0x00800000
    encipherOnly = 0x01000000
    cRLSign = 0x02000000
    keyCertSign = 0x04000000
    keyAgreement = 0x08000000
    dataEncipherment = 0x10000000
    keyEncipherment = 0x20000000
    nonrepudiation_contentCommitment = 0x40000000
    digitalSignature = 0x80000000


@tpm_bitfield()
class TPMA_ACT(UINT32):
    signaled = 0x00000001
    preserveSignaled = 0x00000002
    reserved = 0xFFFFFFFC


# TODO obj describes protocol (bits = _attributes) vs obj is pythonic (bits = properties)
#      better: have a metaclass
