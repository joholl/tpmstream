from tpmstream.spec.common.values import tpm_dataclass
from tpmstream.spec.structures.attribute_structures import TPMA_LOCALITY
from tpmstream.spec.structures.base_types import UINT16
from tpmstream.spec.structures.constants import TPM_ALG_ID
from tpmstream.spec.structures.structures import (
    TPM2B_DATA,
    TPM2B_DIGEST,
    TPM2B_NAME,
    TPML_PCR_SELECTION,
)


@tpm_dataclass
class TPMS_CREATION_DATA:
    pcrSelect: TPML_PCR_SELECTION
    pcrDigest: TPM2B_DIGEST
    locality: TPMA_LOCALITY
    parentNameAlg: TPM_ALG_ID
    parentName: TPM2B_NAME
    parentQualifiedName: TPM2B_NAME
    outsideInfo: TPM2B_DATA


@tpm_dataclass
class TPM2B_CREATION_DATA:
    size: UINT16
    creationData: TPMS_CREATION_DATA
