class TestReadme:
    def test_marshal_from_bytes(self):
        from tpmstream.common.object import events_to_obj
        from tpmstream.io.binary import Binary
        from tpmstream.spec.commands import Command
        from tpmstream.spec.structures.constants import TPM_SU

        events = Binary.marshal(
            tpm_type=Command, buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00"
        )
        command = events_to_obj(events)

        print(command.parameters.startupType)  # prints TPM_SU.CLEAR
        assert command.parameters.startupType == TPM_SU.CLEAR

    def test_marshal_from_command(self):
        from tpmstream.common.object import obj_to_events
        from tpmstream.io.binary import Binary
        from tpmstream.spec.commands import Command
        from tpmstream.spec.commands.commands_handles import (
            TPMS_COMMAND_HANDLES_STARTUP,
        )
        from tpmstream.spec.commands.commands_params import TPMS_COMMAND_PARAMS_STARTUP
        from tpmstream.spec.structures.base_types import UINT32
        from tpmstream.spec.structures.constants import TPM_CC, TPM_ST, TPM_SU
        from tpmstream.spec.structures.interface_types import TPMI_ST_COMMAND_TAG

        startup_command = Command(
            tag=TPMI_ST_COMMAND_TAG(TPM_ST.NO_SESSIONS),
            commandSize=UINT32(12),
            commandCode=TPM_CC.Startup,
            handles=TPMS_COMMAND_HANDLES_STARTUP(),
            parameters=TPMS_COMMAND_PARAMS_STARTUP(startupType=TPM_SU.CLEAR),
        )

        events = obj_to_events(startup_command)
        assert list(events) == list(
            Binary.marshal(
                tpm_type=Command,
                buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00",
            )
        )

    def test_unmarshal(self):
        from tpmstream.io.binary import Binary
        from tpmstream.io.pretty import Pretty
        from tpmstream.spec.commands import Command

        events = Binary.marshal(
            tpm_type=Command, buffer=b"\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00"
        )
        pretty = Pretty.unmarshal(events=events)

        for line in pretty:
            print(line)
