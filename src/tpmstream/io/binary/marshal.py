import itertools
from dataclasses import fields
from typing import Any

from tpmstream.common.event import PATH_NODE_ROOT_NAME, MarshalEvent, Path, PathNode
from tpmstream.common.util import is_list
from tpmstream.spec.commands.commands import Command

# TODO error handling
# TODO * recoverable: yield MarshalErrorEvent?
# TODO * non-recoverable: raise CustomError except MarshalError?
from tpmstream.spec.commands.responses import Response
from tpmstream.spec.structures.constants import TPM_RC, TPM_ST


def marshal_single(tpm_type, buffer, root_path=None, command_code=None):
    """
    Generator.
    Take iterable which yields single bytes.
    Yield MarshalEvents.
    Return (command_code, remaining_bytes)
    command_code is an int or None.
    remaining_bytes is a generator or None if depleted.
    """
    if root_path is None:
        root_path = Path(PathNode(PATH_NODE_ROOT_NAME))
    command_code_path = Path(root_path / PathNode("commandCode"))
    coroutine = process(tpm_type, path=root_path, command_code=command_code)
    buffer_iter = iter(buffer)

    command_code = None
    byte = None
    bytes_remaining = True

    while bytes_remaining:
        # send next byte into coroutine
        event = coroutine.send(byte)

        try:
            byte = next(buffer_iter)
        except StopIteration:
            bytes_remaining = False

        # get events from coroutine until None is yielded
        while event is not None:
            if event is not None and event.path == command_code_path:
                command_code = event.value
            yield event
            try:
                event = coroutine.send(None)
            except StopIteration:
                if bytes_remaining:
                    # put last byte "back in" and return remaining bytes
                    return command_code, itertools.chain((byte,), buffer_iter)
                else:
                    # all bytes were depleted
                    return command_code, None
    return command_code, None


def marshal_all(tpm_type, buffer, root_path=None, command_code=None):
    """Generator. Take iterable which yields single bytes. Yield MarshalEvents."""
    # TODO automatically detect if it is Command/Response?
    remaining = buffer
    while remaining is not None:
        command_code, remaining = yield from marshal_single(
            tpm_type, remaining, root_path=root_path, command_code=command_code
        )
        tpm_type = Command if command_code is None else Response


# TODO assert size for commandSize, authSize -> events?


def assert_size(tpm_type, path, actual, expected):
    """Coroutine. Warn if actual is different from expected."""
    # TODO stderr
    # TODO logging?
    # TODO add index to name
    if actual == expected:
        return
    type_name = f"{Fore.BLUE}{type_get_name(tpm_type)}{Style.RESET_ALL}"
    name = f"{Fore.LIGHTGREEN_EX}{'.'.join(path)}{Style.RESET_ALL}"
    yield f"{Fore.RED}ERROR{Style.RESET_ALL} Expected size of {expected} for {type_name} {name} but got: {actual}"


def assert_key(tpm_type, name, actual, expected):
    """Coroutine. Warn if actual is different from expected."""
    # TODO
    # if actual == expected:
    #     return
    # type_name = f"{Fore.BLUE}{type_get_name(tpm_type)}{Style.RESET_ALL}"
    # name = f"{Fore.LIGHTGREEN_EX}.{name}{Style.RESET_ALL}"
    # yield f"{Fore.RED}ERROR{Style.RESET_ALL} Expected size of {expected} for {type_name} {name} but got: {actual}"


def process_primitive(tpm_type, path):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    size = tpm_type._int_size
    data = []
    for _ in range(size):
        byte = yield None
        data.append(byte)
    value = int.from_bytes(data, byteorder="big")
    none = yield MarshalEvent(path, tpm_type, tpm_type(value))
    assert none is None
    return size, value


def process_array(tpm_type, parent_path, name, count):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    assert len(tpm_type.__args__) == 1
    element_type = tpm_type.__args__[0]

    none = yield MarshalEvent(parent_path / PathNode(name), list[element_type], ...)
    assert none is None

    element_size = 0
    for index in range(count):
        element_size, _ = yield from process(
            element_type, parent_path / PathNode(name, index)
        )
    return element_size * count, None


def process_tpms(tpm_type, path):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    size = 0
    values = {}
    element_size, element_value = None, None
    for field in fields(tpm_type):
        if is_list(field.type):
            # list member
            elements_size, _ = yield from process_array(
                field.type, path, field.name, count=element_value
            )
        elif hasattr(tpm_type, "_selectors") and field.name in tpm_type._selectors:
            # union member
            selector_name = tpm_type._selectors[field.name]
            selector_value = values[selector_name]
            element_size, element_value = yield from process(
                field.type, path / PathNode(field.name), selector=selector_value
            )
        else:
            element_size, element_value = yield from process(
                field.type, path / PathNode(field.name)
            )
        values[field.name] = element_value
        size += element_size
    return size, None


def process_tpm2b(tpm_type, path):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    # A dedicated funtion is needed because the size in TPM2B is always in bytes (not in elements)
    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    size_field, buffer_field = fields(tpm_type)
    size_size, buffer_size_exp = yield from process(
        size_field.type, path / PathNode(size_field.name)
    )
    if is_list(buffer_field.type):
        # common tpm2b with byte buffer
        buffer_size, _ = yield from process_array(
            buffer_field.type, path, buffer_field.name, count=buffer_size_exp
        )
    else:
        # buffer represents single complex type, count is number of bytes
        if buffer_size_exp == 0:
            none = yield MarshalEvent(
                path / PathNode(buffer_field.name), buffer_field.type, ...
            )
            assert none is None
            buffer_size = 0
        else:
            buffer_size, _ = yield from process(
                buffer_field.type, path / PathNode(buffer_field.name)
            )
        # TODO yield from assert_size(tpm_type, path, actual=buffer_size, expected=buffer_size_exp)

    return size_size + buffer_size, None


def process_tpmu(tpm_type, path, selector):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    # TODO _selected_by
    assert hasattr(
        tpm_type, "_selected_by"
    ), f"Union type {tpm_type} must have attribute ._selected_by"
    # reverse dict
    selection = {v: k for k, v in tpm_type._selected_by.items()}
    assert (
        selector in selection
    ), f"Selection error in {path} ({tpm_type.__name__}): {selector} not in {selection}"  # TODO as warning, also check if there is a None (i.e. default) option first
    field = next(f for f in fields(tpm_type) if f.name == selection[selector])

    if field.type is None:
        return 0, None

    if is_list(field.type):
        # union member of list type (must be statically sized as indicated in _list_size)
        assert hasattr(tpm_type, "_list_size")
        size, data = yield from process_array(
            field.type, path, field.name, count=tpm_type._list_size[field.name]
        )
    else:
        size, data = yield from process(field.type, path / PathNode(field.name))

    return size, data


def process_command(path):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    tpm_type = Command

    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    size = 0
    values = {}
    for field in fields(tpm_type):
        field_type = field.type
        if (
            field.name in ("authSize", "authorizationArea")
            and values["tag"] != TPM_ST.SESSIONS
        ):
            continue

        if field_type is Any:
            selector_name = tpm_type._selectors[field.name]
            types_map = tpm_type._type_maps[field.name]
            # TODO warning / error
            assert selector_name in values, f"Did not parse {selector_name} yet."
            selector_value = values[selector_name]
            assert (
                selector_value in types_map
            ), f"Cannot find type for {field.name} (selected by {selector_name}): {selector_value}"
            field_type = types_map[selector_value]

        if field.name == "authorizationArea":
            # authorizationArea is a list with 1-n elements (authSize is size in bytes)
            auth_area_type = field_type.__args__[0]
            none = yield MarshalEvent(path / PathNode(field.name), field_type, ...)
            assert none is None

            auth_area_size_so_far = 0
            index = 0
            while auth_area_size_so_far < values["authSize"]:
                authorizationArea_size, _ = yield from process(
                    auth_area_type, path / PathNode(field.name, index)
                )
                auth_area_size_so_far += authorizationArea_size
                index += 1
            assert (
                auth_area_size_so_far == values["authSize"]
            ), f"Command: authSize is {values['authSize']} but parsing {index} authorizationArea(s) consumed {auth_area_size_so_far} bytes"
            size += auth_area_size_so_far
        else:
            # all other members
            element_size, element_value = yield from process(
                field_type, path / PathNode(field.name)
            )
            size += element_size

        values[field.name] = element_value
    return size, None


def process_response(path, command_code):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    tpm_type = Response

    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    size = 0
    values = {}
    for field in fields(tpm_type):
        field_type = field.type

        if (
            field.name in ("parameterSize", "authorizationArea")
            and values["tag"] != TPM_ST.SESSIONS
        ):
            continue

        if (
            field.name
            in ("handles", "parameterSize", "parameters", "authorizationArea")
            and "responseCode" in values
            and values["responseCode"] != TPM_RC.SUCCESS
        ):
            continue

        if field_type is Any:
            types_map = tpm_type._type_maps[field.name]
            # TODO warning / error
            assert (
                command_code in types_map
            ), f"Cannot find type for {field.name} (selected by commandCode): {command_code}"
            field_type = types_map[command_code]

        if field.name == "authorizationArea":
            # authorizationArea is a list with 1-n elements (remaining bytes)
            auth_area_type = field_type.__args__[0]
            auth_area_size = values["responseSize"] - size
            none = yield MarshalEvent(path / PathNode(field.name), field_type, ...)
            assert none is None

            auth_area_size_so_far = 0
            index = 0
            while auth_area_size_so_far < auth_area_size:
                authorizationArea_size, _ = yield from process(
                    auth_area_type, path / PathNode(field.name, index)
                )
                auth_area_size_so_far += authorizationArea_size
                index += 1
            # TODO why not?
            # try:
            #     assert auth_area_size_so_far == auth_area_size, f"Response: remaining bytes is {auth_area_size} but parsing {index} authorizationArea(s) consumed {auth_area_size_so_far} bytes"
            # except AssertionError as e:
            #     pass # TODO rm
            size += auth_area_size_so_far
        else:
            # all other members
            element_size, element_value = yield from process(
                field_type, path / PathNode(field.name)
            )
            size += element_size

        values[field.name] = element_value
    return size, None


def process(tpm_type, path, selector=None, command_code=None):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    if hasattr(tpm_type, "_int_size"):
        # Primitives, TPMA
        result = yield from process_primitive(tpm_type, path)
    elif tpm_type.__name__.startswith("TPM2B"):
        result = yield from process_tpm2b(tpm_type, path)
    elif hasattr(tpm_type, "_selected_by"):
        # TPMU
        result = yield from process_tpmu(tpm_type, path, selector)
    elif tpm_type is Command:
        result = yield from process_command(path)
    elif tpm_type is Response:
        result = yield from process_response(path, command_code)
    else:
        # TPMS, TPMT, TPML
        result = yield from process_tpms(tpm_type, path)
    return result
