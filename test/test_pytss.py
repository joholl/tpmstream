from dataclasses import fields
from unittest import skip

from tpm2_pytss.constants import TPM2_ALG, TPM2_CAP, TPM2_ECC, TPMA_OBJECT
from tpm2_pytss.types import (
    TPM2B_AUTH,
    TPM2B_DIGEST,
    TPM2B_ECC_PARAMETER,
    TPM2B_ECC_POINT,
    TPM2B_NONCE,
    TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_SENSITIVE_DATA,
    TPML_HANDLE,
    TPMS_CAPABILITY_DATA,
    TPMS_ECC_PARMS,
    TPMS_ECC_POINT,
    TPMS_PCR_SELECTION,
    TPMS_SCHEME_ECDAA,
    TPMS_SENSITIVE_CREATE,
    TPMT_ECC_SCHEME,
    TPMT_KDF_SCHEME,
    TPMT_PUBLIC,
    TPMT_SYM_DEF_OBJECT,
    TPMU_ASYM_SCHEME,
    TPMU_CAPABILITIES,
    TPMU_PUBLIC_ID,
    TPMU_PUBLIC_PARMS,
)

from tpmstream.common.object import events_to_obj
from tpmstream.io.tpm_pytss import TpmPytss
from tpmstream.spec.structures.base_types import BYTE


def assert_equal(pytss_obj, tpmstream_obj, path=""):
    if isinstance(pytss_obj, int):
        assert pytss_obj == int(
            tpmstream_obj
        ), f"{path} differs: {pytss_obj} == {int(tpmstream_obj)}"
        return
    if isinstance(tpmstream_obj, list):
        if len(tpmstream_obj) == 0:
            return
        if isinstance(tpmstream_obj[0], BYTE):
            pytss_bytes = bytes(pytss_obj)
            tpmstream_bytes = bytes(int(b) for b in tpmstream_obj)
            assert (
                pytss_bytes == tpmstream_bytes
            ), f"{path} differs: {pytss_obj} == {tpmstream_obj}"
            return
        for i, tpmstream_element in enumerate(tpmstream_obj):
            assert pytss_obj[i] == tpmstream_element
        return

    # deep equals check
    for tpm_type in fields(tpmstream_obj):
        tpmstream_attr = getattr(tpmstream_obj, tpm_type.name)
        if (
            tpmstream_attr is None
            or type(tpmstream_attr).__name__ == "TPMU_SYM_DETAILS"
        ):  # commented out in the spec
            continue
        pytss_attr = getattr(pytss_obj, tpm_type.name)
        assert_equal(pytss_attr, tpmstream_attr, path=f"{path}.{tpm_type.name}")


class TestConstraintsExceptions:
    def test_tpm2b(self):
        pytss_obj = TPM2B_NONCE(b"\xde\xad\xbe\xef")

        events = TpmPytss.marshal(pytss_obj)
        tpmstream_obj = events_to_obj(events)

        assert_equal(pytss_obj, tpmstream_obj)

    @skip  # TODO pytss bug: buffer is one byte too big
    def test_tpms_pcr_selection(self):
        pytss_obj = TPMS_PCR_SELECTION.parse("sha512:1, 7, 8, 12, 18, 24")

        events = TpmPytss.marshal(pytss_obj)
        tpmstream_obj = events_to_obj(events)

        assert_equal(pytss_obj, tpmstream_obj)

    def test_tpm2b_public(self):
        pytss_obj = TPM2B_PUBLIC(
            size=26,
            publicArea=TPMT_PUBLIC(
                type=TPM2_ALG.ECC,
                nameAlg=TPM2_ALG.SHA256,
                objectAttributes=TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN,
                authPolicy=TPM2B_DIGEST(b""),
                parameters=TPMU_PUBLIC_PARMS(
                    eccDetail=TPMS_ECC_PARMS(
                        symmetric=TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.NULL),
                        scheme=TPMT_ECC_SCHEME(
                            scheme=TPM2_ALG.ECDAA,
                            details=TPMU_ASYM_SCHEME(
                                ecdaa=TPMS_SCHEME_ECDAA(
                                    hashAlg=TPM2_ALG.SHA256,
                                    count=0,
                                ),
                            ),
                        ),
                        curveID=TPM2_ECC.NIST_P256,  # sic!
                        kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
                    ),
                ),
                unique=TPMU_PUBLIC_ID(
                    ecc=TPMS_ECC_POINT(
                        x=TPM2B_ECC_PARAMETER(b""),
                        y=TPM2B_ECC_PARAMETER(b""),
                    ),
                ),
            ),
        )

        events = TpmPytss.marshal(pytss_obj)
        tpmstream_obj = events_to_obj(events)

        assert_equal(pytss_obj, tpmstream_obj)

    def test_tpms_sensitive_create(self):
        pytss_obj = TPM2B_SENSITIVE_CREATE(
            size=11,
            sensitive=TPMS_SENSITIVE_CREATE(
                userAuth=TPM2B_AUTH(b"\xAA\xBB\xCC"),
                data=TPM2B_SENSITIVE_DATA(b"\xC0\xFF\xEB\xAD"),
            ),
        )

        events = TpmPytss.marshal(pytss_obj)
        tpmstream_obj = events_to_obj(events)

        assert_equal(pytss_obj, tpmstream_obj)

    def test_tpm2b_ecc_point(self):
        pytss_obj = TPM2B_ECC_POINT(size=6, point=TPMS_ECC_POINT(x=b"\x01", y="\x02"))

        events = TpmPytss.marshal(pytss_obj)
        tpmstream_obj = events_to_obj(events)

        assert_equal(pytss_obj, tpmstream_obj)

    def test_tpms_capability_data(self):
        pytss_obj = TPMS_CAPABILITY_DATA(
            capability=TPM2_CAP.HANDLES,
            data=TPMU_CAPABILITIES(handles=TPML_HANDLE([1, 2])),
        )

        events = TpmPytss.marshal(pytss_obj)
        tpmstream_obj = events_to_obj(events)

        assert_equal(pytss_obj, tpmstream_obj)

    def test_tpms_capability_data(self):
        pytss_obj = TPMS_CAPABILITY_DATA(
            capability=TPM2_CAP.HANDLES,
            data=TPMU_CAPABILITIES(handles=TPML_HANDLE([1, 2])),
        )

        events = TpmPytss.marshal(pytss_obj)
        tpmstream_obj = events_to_obj(events)

        assert_equal(pytss_obj, tpmstream_obj)
