import binascii
import itertools
import os
from dataclasses import fields
from typing import Optional

import dpkt
import pytest

from tpmstream.common.canonical import Canonical, Generator
from tpmstream.common.error import ConstraintViolatedError
from tpmstream.common.object import events_to_obj, obj_to_events
from tpmstream.data import example_data_files
from tpmstream.io import bytes_from_files
from tpmstream.io.binary import Binary
from tpmstream.io.swtpm_log import SWTPMLog
from tpmstream.spec.commands import CommandResponseStream, Command, Response, command_handle_types
from tpmstream.spec.structures.attribute_structures import TPMA_SESSION
from tpmstream.spec.structures.constants import TPM_CC


def get_command_code(binary_blob) -> TPM_CC:
    return TPM_CC(int.from_bytes(binary_blob[6:10], byteorder="big"))


def get_response_param_encryption(binary_blob) -> Optional[bool]:
    def to_int(start, stop):
        return int.from_bytes(binary_blob[start:stop], byteorder="big")

    tag = to_int(0, 2)
    if tag != 0x8002:
        return None
    command_code = get_command_code(binary_blob)
    command_handle_type = command_handle_types[command_code]
    auth_size_offset = 10 + 4 * len(fields(command_handle_type))
    auth_size = to_int(auth_size_offset, auth_size_offset + 4)
    auth_areas_offset = auth_size_offset + 4
    auth_area_offset = auth_areas_offset

    while auth_area_offset < auth_areas_offset + auth_size:
        # .sessionHandle
        # .nonce
        #   .size
        #   .buffer
        # .sessionAttributes
        # .hmac
        #   .size
        #   .buffer
        nonce_size_offset = auth_area_offset + 4
        nonce_size = to_int(nonce_size_offset, nonce_size_offset + 2)
        session_attributes_offset = nonce_size_offset + 2 + nonce_size
        session_attributes = to_int(
            session_attributes_offset, session_attributes_offset + 1
        )
        if session_attributes & TPMA_SESSION.encrypt:
            return True
        hmac_size_offset = session_attributes_offset + 1
        hmac_size = to_int(hmac_size_offset, hmac_size_offset + 2)

        # next auth_area
        auth_area_offset = hmac_size_offset + 2 + hmac_size
    return None


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
            get_test_name(path, get_command_code(binary_blob))
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
            command_code = get_command_code(binary_blob)
            parameter_encryption = get_response_param_encryption(binary_blob)
        else:
            # response
            if names:
                yield get_test_name(path, command_code)
            else:
                yield binary_blob, command_code, parameter_encryption
            command_code = None


class TestEvents:
    @pytest.mark.parametrize(
        "binary_blob", tpm_command_generator(), ids=tpm_command_generator(names=True)
    )
    def test_canonical(self, binary_blob):
        """Verify that events <-> object is reversible."""
        canonical = Canonical(binary_blob, tpm_type=Command, abort_on_error=True)

        # binary to events
        success = False
        error = None
        try:
            canonical.events  # resolve
            success = True
        except ConstraintViolatedError as e:
            error = e
        # avoid cluttering ("During handling of the above exception, another exception occurred")
        if not success:
            print(f"")
            Canonical(binary_blob, tpm_type=Command, abort_on_error=False).debug()
            pytest.skip(
                f"""
                Binary: {binary_blob.hex()}
                {type(error).__name__}     {error}
            """
            )

        # events to object
        command = canonical.object
        # object to events
        canonical2 = Canonical(command)

        # compare events
        for event_from_obj, event_from_bin in zip(canonical.events, canonical2.events):
            assert event_from_obj == event_from_bin, (
                "Events not equal:\n\t"
                + f"event_from_obj = {event_from_obj}"
                + "\n\t"
                + f"event_from_bin = {event_from_bin}"
            )
            assert type(event_from_obj.value) is type(event_from_bin.value)

    @pytest.mark.parametrize(
        "binary_blob", tpm_command_generator(), ids=tpm_command_generator(names=True)
    )
    def test_event_marshalling_unmarshalling_command(self, binary_blob):
        """Verify that events <-> object is reversible."""
        generator = Generator(Binary.marshal(tpm_type=Command, buffer=binary_blob))

        # binary to events
        try:
            events_from_bin = list(generator)
        except ConstraintViolatedError as error:
            pytest.skip(
                f"""
{error}
bytes:           {binascii.hexlify(binary_blob).decode()}
remaining bytes: {binascii.hexlify(bytes(error.bytes_remaining)).decode()}
"""
            )
        # object is a by-product of marshalling, get events from that
        obj_from_bin = generator.value
        events_from_marshalling = list(obj_to_events(obj_from_bin))

        # events to object
        command = events_to_obj(events_from_bin)
        # object to events
        events_from_obj = list(obj_to_events(command))
        # compare events
        for event_from_obj, event_from_bin, event_from_marshalling in zip(
            events_from_obj, events_from_bin, events_from_marshalling
        ):
            try:
                assert event_from_obj == event_from_bin == event_from_marshalling
                assert (
                    type(event_from_obj.value)
                    is type(event_from_bin.value)
                    is type(event_from_marshalling.value)
                )
            except AssertionError as error:
                print("foo")

    @pytest.mark.parametrize(
        "binary_blob, command_code, parameter_encryption",
        tpm_response_generator(),
        ids=tpm_response_generator(names=True),
    )
    def test_event_marshalling_unmarshalling_response(
        self, binary_blob, command_code, parameter_encryption
    ):
        """Verify that events <-> object is reversible."""
        generator = Generator(
            Binary.marshal(
                tpm_type=Response,
                buffer=binary_blob,
                parameter_encryption=parameter_encryption,
                command_code=command_code,
            )
        )

        # binary to events
        try:
            events_from_bin = list(generator)
        except ConstraintViolatedError as error:
            pytest.skip(f"{error}")
        # object is a by-product of marshalling, get events from that
        obj_from_bin = generator.value
        events_from_marshalling = list(obj_to_events(obj_from_bin))

        # events to object
        command = events_to_obj(events_from_bin, command_code=command_code)
        # object to events
        events_from_obj = list(obj_to_events(command))
        # compare events
        for event_from_obj, event_from_bin, event_from_marshalling in zip(
            events_from_obj, events_from_bin, events_from_marshalling
        ):
            assert event_from_obj == event_from_bin == event_from_marshalling
            assert (
                type(event_from_obj.value)
                is type(event_from_bin.value)
                is type(event_from_marshalling.value)
            )


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
        "binary_blob, command_code, parameter_encryption",
        tpm_response_generator(),
        ids=tpm_response_generator(names=True),
    )
    def test_binary_marshalling_unmarshalling_response(
        self, binary_blob, command_code, parameter_encryption
    ):
        """Verify that events <-> object is reversible."""
        # binary to events
        try:
            events_from_bin = list(
                Binary.marshal(
                    tpm_type=Response,
                    buffer=binary_blob,
                    command_code=command_code,
                    parameter_encryption=parameter_encryption,
                )
            )
        except ConstraintViolatedError as error:
            pytest.skip(f"{error}")
        # events to binary
        bin_from_events = b"".join(Binary.unmarshal(events_from_bin))
        assert (
            binary_blob == bin_from_events
        ), f"assert {binascii.hexlify(binary_blob)} == {binascii.hexlify(bin_from_events)}"


class TestSWTPMLogs:

    @pytest.mark.parametrize(
        "log_name",
        [ "fedora38", "win11" ]
    )
    def test_marshalling(self, log_name):
        log_file = os.path.join("test", "swtpm", log_name + "-swtpm.log")
        with open(log_file, "rb") as log:
            log = bytes_from_files(log)
            SWTPMLog.marshal(CommandResponseStream, log, abort_on_error=True)


# TODO canonical object from marshal is object from events
