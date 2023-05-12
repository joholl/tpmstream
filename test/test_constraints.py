import copy
import itertools

import pytest

from tpmstream.common.error import (
    InputStreamBytesDepletedError,
    InputStreamSuperfluousBytesError,
    SizeConstraintViolatedError,
    ValueConstraintViolatedError,
)
from tpmstream.common.event import Path
from tpmstream.common.object import obj_to_events
from tpmstream.common.path import PATH_NODE_ROOT_NAME, PathNode
from tpmstream.io.binary import Binary
from tpmstream.spec.commands import Command, CommandResponseStream, Response
from tpmstream.spec.commands.commands_handles import (
    TPMS_COMMAND_HANDLES_CREATE_PRIMARY,
    TPMS_COMMAND_HANDLES_STARTUP,
)
from tpmstream.spec.commands.commands_params import (
    TPMS_COMMAND_PARAMS_CREATE_PRIMARY,
    TPMS_COMMAND_PARAMS_STARTUP,
)
from tpmstream.spec.commands.responses_handles import TPMS_RESPONSE_HANDLES_STARTUP
from tpmstream.spec.commands.responses_params import TPMS_RESPONSE_PARAMS_STARTUP
from tpmstream.spec.structures.algorithm_parameters_and_structures import (
    TPM2B_ECC_PARAMETER,
    TPM2B_SENSITIVE_CREATE,
    TPM2B_SENSITIVE_DATA,
    TPMI_AES_KEY_BITS,
    TPMI_ECC_CURVE,
    TPMS_ECC_POINT,
    TPMS_SENSITIVE_CREATE,
    TPMS_SIG_SCHEME_ECDAA,
    TPMS_SYMCIPHER_PARMS,
    TPMT_ECC_SCHEME,
    TPMT_KDF_SCHEME,
    TPMT_SYM_DEF_OBJECT,
    TPMU_ASYM_SCHEME,
    TPMU_SYM_DETAILS,
    TPMU_SYM_KEY_BITS,
    TPMU_SYM_MODE,
)
from tpmstream.spec.structures.attribute_structures import TPMA_OBJECT
from tpmstream.spec.structures.base_types import BYTE, UINT16, UINT32
from tpmstream.spec.structures.constants import TPM_ALG, TPM_CC, TPM_RC, TPM_ST, TPM_SU
from tpmstream.spec.structures.handles import TPM_RH
from tpmstream.spec.structures.interface_types import TPMI_ALG_HASH, TPMI_ALG_SYM_OBJECT
from tpmstream.spec.structures.key_object_complex import (
    TPM2B_PUBLIC,
    TPMS_ECC_PARMS,
    TPMT_PUBLIC,
    TPMU_PUBLIC_ID,
    TPMU_PUBLIC_PARMS,
)
from tpmstream.spec.structures.structures import (
    TPM2B_AUTH,
    TPM2B_DATA,
    TPM2B_DIGEST,
    TPML_PCR_SELECTION,
)

startup_command = Command(
    tag=TPM_ST.NO_SESSIONS,
    commandSize=UINT32(12),
    commandCode=TPM_CC.Startup,
    handles=TPMS_COMMAND_HANDLES_STARTUP(),
    parameters=TPMS_COMMAND_PARAMS_STARTUP(startupType=TPM_SU.CLEAR),
)

startup_response = Response(
    tag=TPM_ST.NO_SESSIONS,
    responseSize=UINT32(10),
    responseCode=TPM_RC.SUCCESS,
    handles=TPMS_RESPONSE_HANDLES_STARTUP(),
    parameters=TPMS_RESPONSE_PARAMS_STARTUP(),
)

create_primary_command = Command(
    tag=TPM_ST.NO_SESSIONS,
    commandSize=UINT32(56),
    commandCode=TPM_CC.CreatePrimary,
    handles=TPMS_COMMAND_HANDLES_CREATE_PRIMARY(primaryHandle=TPM_RH.OWNER),
    parameters=TPMS_COMMAND_PARAMS_CREATE_PRIMARY(
        inSensitive=TPM2B_SENSITIVE_CREATE(
            size=UINT16(4),
            sensitive=TPMS_SENSITIVE_CREATE(
                userAuth=TPM2B_AUTH(size=UINT16(0)),
                data=TPM2B_SENSITIVE_DATA(size=UINT16(0)),
            ),
        ),
        inPublic=TPM2B_PUBLIC(
            size=UINT16(26),
            publicArea=TPMT_PUBLIC(
                type=TPM_ALG.ECC,
                nameAlg=TPM_ALG.SHA256,
                objectAttributes=TPMA_OBJECT(0x00040072),
                authPolicy=TPM2B_DIGEST(size=UINT16(0)),
                parameters=TPMU_PUBLIC_PARMS(
                    eccDetail=TPMS_ECC_PARMS(
                        symmetric=TPMT_SYM_DEF_OBJECT(algorithm=TPM_ALG.NULL),
                        scheme=TPMT_ECC_SCHEME(
                            scheme=TPM_ALG.ECDAA,
                            details=TPMU_ASYM_SCHEME(
                                ecdaa=TPMS_SIG_SCHEME_ECDAA(
                                    hashAlg=TPM_ALG.SHA256,
                                    count=UINT16(0),
                                ),
                            ),
                        ),
                        curveID=TPMI_ECC_CURVE.NIST_P256,
                        kdf=TPMT_KDF_SCHEME(scheme=TPM_ALG.NULL),
                    ),
                ),
                unique=TPMU_PUBLIC_ID(
                    ecc=TPMS_ECC_POINT(
                        x=TPM2B_ECC_PARAMETER(size=UINT16(0)),
                        y=TPM2B_ECC_PARAMETER(size=UINT16(0)),
                    ),
                ),
            ),
        ),
        outsideInfo=TPM2B_DATA(
            size=UINT16(2), buffer=list[BYTE]([BYTE(0xAA), BYTE(0xBB)])
        ),
        creationPCR=TPML_PCR_SELECTION(count=UINT32(0)),
    ),
)


create_primary_sym_command = Command(
    tag=TPM_ST.NO_SESSIONS,
    commandSize=UINT32(56),
    commandCode=TPM_CC.CreatePrimary,
    handles=TPMS_COMMAND_HANDLES_CREATE_PRIMARY(primaryHandle=TPM_RH.OWNER),
    parameters=TPMS_COMMAND_PARAMS_CREATE_PRIMARY(
        inSensitive=TPM2B_SENSITIVE_CREATE(
            size=UINT16(4),
            sensitive=TPMS_SENSITIVE_CREATE(
                userAuth=TPM2B_AUTH(size=UINT16(0)),
                data=TPM2B_SENSITIVE_DATA(size=UINT16(0)),
            ),
        ),
        inPublic=TPM2B_PUBLIC(
            size=UINT16(26),
            publicArea=TPMT_PUBLIC(
                type=TPM_ALG.SYMCIPHER,
                nameAlg=TPM_ALG.SHA256,
                objectAttributes=TPMA_OBJECT(0x00040072),
                authPolicy=TPM2B_DIGEST(size=UINT16(0)),
                parameters=TPMU_PUBLIC_PARMS(
                    symDetail=TPMS_SYMCIPHER_PARMS(
                        sym=TPMT_SYM_DEF_OBJECT(
                            algorithm=TPM_ALG.AES,
                            keyBits=TPMU_SYM_KEY_BITS(aes=TPMI_AES_KEY_BITS(256)),
                            mode=TPMU_SYM_MODE(aes=TPM_ALG.CBC),
                            details=TPMU_SYM_DETAILS(aes=None),
                        ),
                    ),
                ),
                unique=TPMU_PUBLIC_ID(
                    sym=TPM2B_DIGEST(
                        size=UINT16(0),
                    ),
                ),
            ),
        ),
        outsideInfo=TPM2B_DATA(
            size=UINT16(2), buffer=list[BYTE]([BYTE(0xAA), BYTE(0xBB)])
        ),
        creationPCR=TPML_PCR_SELECTION(count=UINT32(0)),
    ),
)


class TestConstraintsExceptions:
    def test_startup_success(self):
        startup_command_events = obj_to_events(startup_command)
        startup_command_binary = b"".join(
            b for b in Binary.unmarshal(events=startup_command_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_command_binary
        )

        # process the events
        list(events_generator)

    def test_create_primary_success(self):
        create_primary_events = obj_to_events(create_primary_command)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary
        )

        # process the events
        list(events_generator)

    def test_command_response_success(self):
        startup_command0_events = obj_to_events(startup_command)
        startup_response0_events = obj_to_events(startup_response)
        startup_command1_events = obj_to_events(startup_command)
        startup_response1_events = obj_to_events(startup_response)
        events = itertools.chain(
            startup_command0_events,
            startup_response0_events,
            startup_command1_events,
            startup_response1_events,
        )
        binary = b"".join(b for b in Binary.unmarshal(events=events))

        events_generator = Binary.marshal(tpm_type=CommandResponseStream, buffer=binary)

        # process the events
        list(events_generator)

    def test_command_response_input_exhausted_before_done_parsing(self):
        startup_command0_events = obj_to_events(startup_command)
        startup_response0_events = obj_to_events(startup_response)
        startup_command1_events = obj_to_events(startup_command)
        startup_response1_events = obj_to_events(startup_response)
        events = itertools.chain(
            startup_command0_events,
            startup_response0_events,
            startup_command1_events,
            startup_response1_events,
        )
        binary = b"".join(b for b in Binary.unmarshal(events=events))
        binary = binary[:-1]

        events_generator = Binary.marshal(tpm_type=CommandResponseStream, buffer=binary)

        # process the events
        with pytest.raises(InputStreamBytesDepletedError) as exc_info:
            list(events_generator)

        assert exc_info.value.command_code == TPM_CC.Startup

    def test_command_code_invalid(self):
        """An invalid command code is fatal."""
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.commandCode._value = 0xFFF
        startup_events = obj_to_events(startup_command_wrong)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))

        events_generator = Binary.marshal(tpm_type=Command, buffer=startup_binary)

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPM_CC
        assert exc_info.value.constraint.constraint_path == Path(
            PathNode(PATH_NODE_ROOT_NAME)
        ) / PathNode("commandCode")
        assert exc_info.value.value == startup_command_wrong.commandCode._value
        assert set(exc_info.value.constraint.valid_values) == set(TPM_CC)

    def test_command_size_exhausted_before_done_parsing(self):
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.commandSize._value -= 1
        startup_events = obj_to_events(startup_command_wrong)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))

        events_generator = Binary.marshal(tpm_type=Command, buffer=startup_binary)

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".commandSize"
        )
        assert (
            exc_info.value.constraint.size_already == startup_command_wrong.commandSize
        )
        assert exc_info.value.constraint.size_max == startup_command_wrong.commandSize
        assert not exc_info.value.constraint.is_obsolete
        assert exc_info.value.violator_path == Path.from_string(
            ".parameters.startupType"
        )

    def test_done_parsing_before_command_size_exhausted(self):
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.commandSize._value += 1
        startup_events = obj_to_events(startup_command_wrong)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))

        events_generator = Binary.marshal(tpm_type=Command, buffer=startup_binary)

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".commandSize"
        )
        assert exc_info.value.constraint.size_already == len(startup_binary)
        assert exc_info.value.constraint.size_max == startup_command_wrong.commandSize
        assert not exc_info.value.constraint.is_obsolete
        assert exc_info.value.violator_path is None

    def test_input_exhausted_before_done_parsing(self):
        startup_events = obj_to_events(startup_command)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))
        # remove one byte so input stream is depleted too early
        startup_binary = startup_binary[:-1]

        events_generator = Binary.marshal(tpm_type=Command, buffer=startup_binary)

        with pytest.raises(InputStreamBytesDepletedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.command_code == startup_command.commandCode

    def test_done_parsing_before_input_exhausted(self):
        superfluous_bytes = b"\x00"

        startup_events = obj_to_events(startup_command)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))
        # remove one byte so input stream is depleted too early
        startup_binary = startup_binary + superfluous_bytes

        events_generator = Binary.marshal(tpm_type=Command, buffer=startup_binary)

        with pytest.raises(InputStreamSuperfluousBytesError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.command_code == startup_command.commandCode
        assert exc_info.value.bytes_remaining == superfluous_bytes

    def test_invalid_selector(self):
        create_primary_sym_command_wrong = copy.deepcopy(create_primary_sym_command)
        create_primary_sym_command_wrong.parameters.inPublic.publicArea.parameters.symDetail.sym.algorithm._value = (
            TPM_ALG.ERROR
        )

        create_primary_events = obj_to_events(create_primary_sym_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary
        )

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPMI_ALG_SYM_OBJECT
        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.publicArea.parameters.symDetail.sym.algorithm"
        )
        assert exc_info.value.value == TPM_ALG.ERROR
        assert set(exc_info.value.constraint.valid_values) == set(
            TPMI_ALG_SYM_OBJECT._valid_values
        )

        # TODO assert remaining bytes

    def test_invalid_value(self):
        create_primary_command_wrong = copy.deepcopy(create_primary_sym_command)
        create_primary_command_wrong.parameters.inPublic.publicArea.nameAlg._value = (
            TPM_ALG.ERROR
        )

        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary
        )

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPMI_ALG_HASH
        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.publicArea.nameAlg"
        )
        assert exc_info.value.value == TPM_ALG.ERROR
        assert set(exc_info.value.constraint.valid_values) == set(
            TPMI_ALG_HASH._valid_values
        )

        # TODO assert remaining bytes

    def test_invalid_value_different_type(self):
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.parameters.startupType._value = 42

        startup_command_events = obj_to_events(startup_command_wrong)
        startup_command_binary = b"".join(
            b for b in Binary.unmarshal(events=startup_command_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_command_binary
        )

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPM_SU
        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.startupType"
        )
        assert exc_info.value.value == TPM_SU(42)
        assert set(exc_info.value.constraint.valid_values) == set(TPM_SU)
        assert bytes(exc_info.value.bytes_remaining) == b""

    def test_tpm2b_size_exhausted_before_done_parsing_body(self):
        size_too_short_by_bytes = 1

        create_primary_command_wrong = copy.deepcopy(create_primary_command)
        # size is too small by <size_too_short_by_bytes> bytes
        create_primary_command_wrong.parameters.inPublic.size._value -= (
            size_too_short_by_bytes
        )
        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.size"
        )
        assert not exc_info.value.constraint.is_obsolete
        assert (
            exc_info.value.constraint.size_already
            == create_primary_command_wrong.parameters.inPublic.size._value
        )
        assert (
            exc_info.value.constraint.size_max
            == create_primary_command_wrong.parameters.inPublic.size._value
        )

        # remaining bytes: size of in_public is short by <size_too_short_by_bytes>
        # i.e. we got the last <size_too_short_by_bytes> bytes of in_public +  the remaining fields outside_info and
        # creation_pcr
        outside_info_events = obj_to_events(
            create_primary_command_wrong.parameters.outsideInfo
        )
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        events = itertools.chain(
            outside_info_events,
            creation_pcr_events,
        )
        remaining_fields_bytes = b"".join(b for b in Binary.unmarshal(events))

        idx_remaining_fields = len(create_primary_binary) - len(remaining_fields_bytes)
        in_public_last_bytes = create_primary_binary[
            idx_remaining_fields - size_too_short_by_bytes : idx_remaining_fields
        ]
        assert (
            bytes(exc_info.value.bytes_remaining)
            == in_public_last_bytes + remaining_fields_bytes
        )

    def test_tpm2b_done_parsing_body_before_size_exhausted(self):
        size_too_long_by_bytes = 1

        create_primary_command_wrong = copy.deepcopy(create_primary_command)
        # size is too long small by <size_too_long_by_bytes> bytes
        create_primary_command_wrong.parameters.inPublic.size._value += (
            size_too_long_by_bytes
        )
        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.size"
        )
        assert not exc_info.value.constraint.is_obsolete
        assert (
            exc_info.value.constraint.size_already + size_too_long_by_bytes
            == create_primary_command_wrong.parameters.inPublic.size._value
        )
        assert (
            exc_info.value.constraint.size_max
            == create_primary_command_wrong.parameters.inPublic.size._value
        )

        # remaining bytes are the remaining fields after the tpm2b in_public: outside_info and creation_pcr
        # the one additional byte (due to the increment of in_public.size) is not parsed, yet, and part of the remaining bytes
        outside_info_events = obj_to_events(
            create_primary_command_wrong.parameters.outsideInfo
        )
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        events = itertools.chain(
            outside_info_events,
            creation_pcr_events,
        )
        remaining_fields_bytes = b"".join(b for b in Binary.unmarshal(events))
        assert bytes(exc_info.value.bytes_remaining) == remaining_fields_bytes

    def test_tpm2b_anticipate_command_size_exhausted_before_done_parsing(self):
        create_primary_command_wrong = copy.deepcopy(create_primary_command)
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        creation_pcr_bytes = b"".join(b for b in Binary.unmarshal(creation_pcr_events))
        # size is so long, that it would overshoot command_size by 1 byte when parsing
        size_too_long_by_bytes = len(creation_pcr_bytes) + 1
        create_primary_command_wrong.parameters.outsideInfo.size._value += (
            size_too_long_by_bytes
        )
        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".commandSize"
        )
        assert not exc_info.value.constraint.is_obsolete
        assert (
            exc_info.value.constraint.size_already
            + create_primary_command_wrong.parameters.outsideInfo.size._value
            == create_primary_command_wrong.commandSize + 1
        )
        assert (
            exc_info.value.constraint.size_max
            == create_primary_command_wrong.commandSize
        )
        assert exc_info.value.violator_path == Path.from_string(
            ".parameters.outsideInfo.size"
        )

        # remaining bytes everything after the offending size field
        outside_info_events = obj_to_events(
            create_primary_command_wrong.parameters.outsideInfo.buffer
        )
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        events = itertools.chain(
            outside_info_events,
            creation_pcr_events,
        )
        remaining_fields_bytes = b"".join(b for b in Binary.unmarshal(events))

        assert bytes(exc_info.value.bytes_remaining) == remaining_fields_bytes


class TestConstraintsEvents:
    def test_startup_success(self):
        startup_command_events = obj_to_events(startup_command)
        startup_command_binary = b"".join(
            b for b in Binary.unmarshal(events=startup_command_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_command_binary, abort_on_error=True
        )

        # process the events
        list(events_generator)

    def test_create_primary_success(self):
        create_primary_events = obj_to_events(create_primary_command)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary, abort_on_error=True
        )

        # process the events
        list(events_generator)

    def test_command_response_success(self):
        startup_command0_events = obj_to_events(startup_command)
        startup_response0_events = obj_to_events(startup_response)
        startup_command1_events = obj_to_events(startup_command)
        startup_response1_events = obj_to_events(startup_response)
        events = itertools.chain(
            startup_command0_events,
            startup_response0_events,
            startup_command1_events,
            startup_response1_events,
        )
        binary = b"".join(b for b in Binary.unmarshal(events=events))

        events_generator = Binary.marshal(
            tpm_type=CommandResponseStream, buffer=binary, abort_on_error=True
        )

        # process the events
        list(events_generator)

    def test_command_response_input_exhausted_before_done_parsing(self):
        startup_command0_events = obj_to_events(startup_command)
        startup_response0_events = obj_to_events(startup_response)
        startup_command1_events = obj_to_events(startup_command)
        startup_response1_events = obj_to_events(startup_response)
        events = itertools.chain(
            startup_command0_events,
            startup_response0_events,
            startup_command1_events,
            startup_response1_events,
        )
        binary = b"".join(b for b in Binary.unmarshal(events=events))
        binary = binary[:-1]

        events_generator = Binary.marshal(
            tpm_type=CommandResponseStream, buffer=binary, abort_on_error=True
        )

        # process the events
        with pytest.raises(InputStreamBytesDepletedError) as exc_info:
            list(events_generator)

        assert exc_info.value.command_code == TPM_CC.Startup

    def test_command_code_invalid(self):
        """An invalid command code is fatal."""
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.commandCode._value = 0xFFF
        startup_events = obj_to_events(startup_command_wrong)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_binary, abort_on_error=True
        )

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPM_CC
        assert exc_info.value.constraint.constraint_path == Path(
            PathNode(PATH_NODE_ROOT_NAME)
        ) / PathNode("commandCode")
        assert exc_info.value.value == startup_command_wrong.commandCode._value
        assert set(exc_info.value.constraint.valid_values) == set(TPM_CC)

    def test_command_size_exhausted_before_done_parsing(self):
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.commandSize._value -= 1
        startup_events = obj_to_events(startup_command_wrong)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_binary, abort_on_error=True
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".commandSize"
        )
        assert (
            exc_info.value.constraint.size_already == startup_command_wrong.commandSize
        )
        assert exc_info.value.constraint.size_max == startup_command_wrong.commandSize
        assert not exc_info.value.constraint.is_obsolete
        assert exc_info.value.violator_path == Path.from_string(
            ".parameters.startupType"
        )

    def test_done_parsing_before_command_size_exhausted(self):
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.commandSize._value += 1
        startup_events = obj_to_events(startup_command_wrong)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_binary, abort_on_error=True
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".commandSize"
        )
        assert exc_info.value.constraint.size_already == len(startup_binary)
        assert exc_info.value.constraint.size_max == startup_command_wrong.commandSize
        assert not exc_info.value.constraint.is_obsolete
        assert exc_info.value.violator_path is None

    def test_input_exhausted_before_done_parsing(self):
        startup_events = obj_to_events(startup_command)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))
        # remove one byte so input stream is depleted too early
        startup_binary = startup_binary[:-1]

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_binary, abort_on_error=True
        )

        with pytest.raises(InputStreamBytesDepletedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.command_code == startup_command.commandCode

    def test_done_parsing_before_input_exhausted(self):
        superfluous_bytes = b"\x00"

        startup_events = obj_to_events(startup_command)
        startup_binary = b"".join(b for b in Binary.unmarshal(events=startup_events))
        # remove one byte so input stream is depleted too early
        startup_binary = startup_binary + superfluous_bytes

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_binary, abort_on_error=True
        )

        with pytest.raises(InputStreamSuperfluousBytesError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.command_code == startup_command.commandCode
        assert exc_info.value.bytes_remaining == superfluous_bytes

    def test_invalid_selector(self):
        create_primary_sym_command_wrong = copy.deepcopy(create_primary_sym_command)
        create_primary_sym_command_wrong.parameters.inPublic.publicArea.parameters.symDetail.sym.algorithm._value = (
            TPM_ALG.ERROR
        )

        create_primary_events = obj_to_events(create_primary_sym_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary, abort_on_error=True
        )

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPMI_ALG_SYM_OBJECT
        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.publicArea.parameters.symDetail.sym.algorithm"
        )
        assert exc_info.value.value == TPM_ALG.ERROR
        assert set(exc_info.value.constraint.valid_values) == set(
            TPMI_ALG_SYM_OBJECT._valid_values
        )

        # TODO assert remaining bytes

    def test_invalid_value(self):
        create_primary_command_wrong = copy.deepcopy(create_primary_sym_command)
        create_primary_command_wrong.parameters.inPublic.publicArea.nameAlg._value = (
            TPM_ALG.ERROR
        )

        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary, abort_on_error=True
        )

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPMI_ALG_HASH
        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.publicArea.nameAlg"
        )
        assert exc_info.value.value == TPM_ALG.ERROR
        assert set(exc_info.value.constraint.valid_values) == set(
            TPMI_ALG_HASH._valid_values
        )

        # TODO assert remaining bytes

    def test_invalid_value_different_type(self):
        startup_command_wrong = copy.deepcopy(startup_command)
        startup_command_wrong.parameters.startupType._value = 42

        startup_command_events = obj_to_events(startup_command_wrong)
        startup_command_binary = b"".join(
            b for b in Binary.unmarshal(events=startup_command_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=startup_command_binary, abort_on_error=True
        )

        with pytest.raises(ValueConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.tpm_type is TPM_SU
        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.startupType"
        )
        assert exc_info.value.value == TPM_SU(42)
        assert set(exc_info.value.constraint.valid_values) == set(TPM_SU)
        assert bytes(exc_info.value.bytes_remaining) == b""

    def test_tpm2b_size_exhausted_before_done_parsing_body(self):
        size_too_short_by_bytes = 1

        create_primary_command_wrong = copy.deepcopy(create_primary_command)
        # size is too small by <size_too_short_by_bytes> bytes
        create_primary_command_wrong.parameters.inPublic.size._value -= (
            size_too_short_by_bytes
        )
        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary, abort_on_error=True
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.size"
        )
        assert not exc_info.value.constraint.is_obsolete
        assert (
            exc_info.value.constraint.size_already
            == create_primary_command_wrong.parameters.inPublic.size._value
        )
        assert (
            exc_info.value.constraint.size_max
            == create_primary_command_wrong.parameters.inPublic.size._value
        )

        # remaining bytes: size of in_public is short by <size_too_short_by_bytes>
        # i.e. we got the last <size_too_short_by_bytes> bytes of in_public +  the remaining fields outside_info and
        # creation_pcr
        outside_info_events = obj_to_events(
            create_primary_command_wrong.parameters.outsideInfo
        )
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        events = itertools.chain(
            outside_info_events,
            creation_pcr_events,
        )
        remaining_fields_bytes = b"".join(b for b in Binary.unmarshal(events))

        idx_remaining_fields = len(create_primary_binary) - len(remaining_fields_bytes)
        in_public_last_bytes = create_primary_binary[
            idx_remaining_fields - size_too_short_by_bytes : idx_remaining_fields
        ]
        assert (
            bytes(exc_info.value.bytes_remaining)
            == in_public_last_bytes + remaining_fields_bytes
        )

    def test_tpm2b_done_parsing_body_before_size_exhausted(self):
        size_too_long_by_bytes = 1

        create_primary_command_wrong = copy.deepcopy(create_primary_command)
        # size is too long small by <size_too_long_by_bytes> bytes
        create_primary_command_wrong.parameters.inPublic.size._value += (
            size_too_long_by_bytes
        )
        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary, abort_on_error=True
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".parameters.inPublic.size"
        )
        assert not exc_info.value.constraint.is_obsolete
        assert (
            exc_info.value.constraint.size_already + size_too_long_by_bytes
            == create_primary_command_wrong.parameters.inPublic.size._value
        )
        assert (
            exc_info.value.constraint.size_max
            == create_primary_command_wrong.parameters.inPublic.size._value
        )

        # remaining bytes are the remaining fields after the tpm2b in_public: outside_info and creation_pcr
        # the one additional byte (due to the increment of in_public.size) is not parsed, yet, and part of the remaining bytes
        outside_info_events = obj_to_events(
            create_primary_command_wrong.parameters.outsideInfo
        )
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        events = itertools.chain(
            outside_info_events,
            creation_pcr_events,
        )
        remaining_fields_bytes = b"".join(b for b in Binary.unmarshal(events))
        assert bytes(exc_info.value.bytes_remaining) == remaining_fields_bytes

    def test_tpm2b_anticipate_command_size_exhausted_before_done_parsing(self):
        create_primary_command_wrong = copy.deepcopy(create_primary_command)
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        creation_pcr_bytes = b"".join(b for b in Binary.unmarshal(creation_pcr_events))
        # size is so long, that it would overshoot command_size by 1 byte when parsing
        size_too_long_by_bytes = len(creation_pcr_bytes) + 1
        create_primary_command_wrong.parameters.outsideInfo.size._value += (
            size_too_long_by_bytes
        )
        create_primary_events = obj_to_events(create_primary_command_wrong)
        create_primary_binary = b"".join(
            b for b in Binary.unmarshal(events=create_primary_events)
        )

        events_generator = Binary.marshal(
            tpm_type=Command, buffer=create_primary_binary, abort_on_error=True
        )

        with pytest.raises(SizeConstraintViolatedError) as exc_info:
            # process the events
            list(events_generator)

        assert exc_info.value.constraint.constraint_path == Path.from_string(
            ".commandSize"
        )
        assert not exc_info.value.constraint.is_obsolete
        assert (
            exc_info.value.constraint.size_already
            + create_primary_command_wrong.parameters.outsideInfo.size._value
            == create_primary_command_wrong.commandSize + 1
        )
        assert (
            exc_info.value.constraint.size_max
            == create_primary_command_wrong.commandSize
        )
        assert exc_info.value.violator_path == Path.from_string(
            ".parameters.outsideInfo.size"
        )

        # remaining bytes everything after the offending size field
        outside_info_events = obj_to_events(
            create_primary_command_wrong.parameters.outsideInfo.buffer
        )
        creation_pcr_events = obj_to_events(
            create_primary_command_wrong.parameters.creationPCR
        )
        events = itertools.chain(
            outside_info_events,
            creation_pcr_events,
        )
        remaining_fields_bytes = b"".join(b for b in Binary.unmarshal(events))

        assert bytes(exc_info.value.bytes_remaining) == remaining_fields_bytes
