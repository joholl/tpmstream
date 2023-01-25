import binascii
import itertools
import os

import dpkt
import pytest

from tpmstream.common.canonical import Canonical
from tpmstream.common.error import ConstraintViolatedError
from tpmstream.common.object import events_to_obj, obj_to_events
from tpmstream.data import example_data_files
from tpmstream.io.binary import Binary
from tpmstream.spec.commands import Command, Response
from tpmstream.spec.structures.constants import TPM_CC


def get_comand_code(binary_blob) -> TPM_CC:
    return TPM_CC(int.from_bytes(binary_blob[6:10], byteorder="big"))


def get_test_name(path, command_code):
    file_basename = os.path.basename(path).split(".")[0]
    # remove leading "TPM_CC_"
    command_code = str(command_code)[len(TPM_CC.__name__) + 1 :]
    return f"{file_basename}_{command_code}"


def tpm_binary_blob_generator():
    for example_data_file in example_data_files:
        with open(example_data_file, "rb") as file:
            pcapng = dpkt.pcapng.Reader(file)
            for ts, buf in pcapng:
                # command or response
                binary_blob = dpkt.ip.IP(buf).data.data
                yield example_data_file, binary_blob


def tpm_command_generator(names=False):
    binary_blob_gen = tpm_binary_blob_generator()
    if names:
        yield from (
            get_test_name(path, get_comand_code(binary_blob))
            for path, binary_blob in itertools.islice(binary_blob_gen, 0, None, 2)
        )
        return

    yield from (
        binary_blob
        for path, binary_blob in itertools.islice(binary_blob_gen, 0, None, 2)
    )


def tpm_response_generator(names=False):
    binary_blob_gen = tpm_binary_blob_generator()

    command_code = None
    for path, binary_blob in binary_blob_gen:
        if command_code is None:
            # command
            command_code = get_comand_code(binary_blob)
        else:
            # response
            if names:
                yield get_test_name(path, command_code)
            else:
                yield binary_blob, command_code
            command_code = None


class TestEvents:
    @pytest.mark.parametrize(
        "binary_blob", tpm_command_generator(), ids=tpm_command_generator(names=True)
    )
    def test_canonical(self, binary_blob):
        """Verify that events <-> object is reversible."""
        canonical = Canonical(binary_blob, tpm_type=Command)

        # binary to events
        try:
            canonical.events  # resolve
        except ConstraintViolatedError as error:
            pytest.skip(
                f"""
    {error}
    bytes:           {binascii.hexlify(binary_blob).decode()}
    remaining bytes: {binascii.hexlify(bytes(error.bytes_remaining)).decode()}
    """
            )
        # events to object
        command = canonical.object
        # object to events
        canonical2 = Canonical(command)
        # compare events
        for event_from_obj, event_from_bin in zip(canonical.events, canonical2.events):
            assert event_from_obj == event_from_bin
            assert type(event_from_obj.value) is type(event_from_bin.value)

    @pytest.mark.parametrize(
        "binary_blob", tpm_command_generator(), ids=tpm_command_generator(names=True)
    )
    def test_event_marshalling_unmarshalling_command(self, binary_blob):
        """Verify that events <-> object is reversible."""
        # binary to events
        try:
            events_from_bin = list(Binary.marshal(tpm_type=Command, buffer=binary_blob))
        except ConstraintViolatedError as error:
            pytest.skip(
                f"""
{error}
bytes:           {binascii.hexlify(binary_blob).decode()}
remaining bytes: {binascii.hexlify(bytes(error.bytes_remaining)).decode()}
"""
            )
        # events to object
        command = events_to_obj(events_from_bin)
        # object to events
        events_from_obj = list(obj_to_events(command))
        # compare events
        for event_from_obj, event_from_bin in zip(events_from_obj, events_from_bin):
            assert event_from_obj == event_from_bin
            assert type(event_from_obj.value) is type(event_from_bin.value)

    @pytest.mark.parametrize(
        "binary_blob, command_code",
        tpm_response_generator(),
        ids=tpm_response_generator(names=True),
    )
    def test_event_marshalling_unmarshalling_response(self, binary_blob, command_code):
        """Verify that events <-> object is reversible."""
        # binary to events
        try:
            events_from_bin = list(
                Binary.marshal(
                    tpm_type=Response, buffer=binary_blob, command_code=command_code
                )
            )
        except ConstraintViolatedError as error:
            pytest.skip(f"{error}")
        # events to object
        command = events_to_obj(events_from_bin, command_code=command_code)
        # object to events
        events_from_obj = list(obj_to_events(command))
        # compare events
        for event_from_obj, event_from_bin in zip(events_from_obj, events_from_bin):
            assert event_from_obj == event_from_bin
            assert type(event_from_obj.value) is type(event_from_bin.value)


class TestBinary:
    @pytest.mark.parametrize(
        "binary_blob", tpm_command_generator(), ids=tpm_command_generator(names=True)
    )
    def test_binary_marshalling_unmarshalling_command(self, binary_blob):
        """Verify that events <-> object is reversible."""
        # binary to events
        try:
            events_from_bin = list(Binary.marshal(tpm_type=Command, buffer=binary_blob))
        except ConstraintViolatedError as error:
            pytest.skip(f"{error}")
        # events to binary
        bin_from_events = b"".join(Binary.unmarshal(events_from_bin))

        assert (
            binary_blob == bin_from_events
        ), f"assert {binascii.hexlify(binary_blob)} == {binascii.hexlify(bin_from_events)}"

    @pytest.mark.parametrize(
        "binary_blob, command_code",
        tpm_response_generator(),
        ids=tpm_response_generator(names=True),
    )
    def test_binary_marshalling_unmarshalling_response(self, binary_blob, command_code):
        """Verify that events <-> object is reversible."""
        # binary to events
        try:
            events_from_bin = list(
                Binary.marshal(
                    tpm_type=Response, buffer=binary_blob, command_code=command_code
                )
            )
        except ConstraintViolatedError as error:
            pytest.skip(f"{error}")
        # events to binary
        bin_from_events = b"".join(Binary.unmarshal(events_from_bin))
        assert (
            binary_blob == bin_from_events
        ), f"assert {binascii.hexlify(binary_blob)} == {binascii.hexlify(bin_from_events)}"
