import itertools
from dataclasses import fields
from typing import Any

from ...common.constraints import SizeConstraint, SizeConstraintList, ValueConstraint
from ...common.error import (
    ConstraintViolatedError,
    InputStreamBytesDepletedError,
    InputStreamSuperfluousBytesError,
    ValueConstraintViolatedError,
)
from ...common.event import MarshalEvent, Path, WarningEvent
from ...common.path import PATH_NODE_ROOT_NAME, PathNode
from ...common.util import is_list
from ...spec.commands import Command, CommandResponseStream, Response
from ...spec.common.values import ValidValues
from ...spec.structures.constants import TPM_CC, TPM_RC, TPM_ST


def marshal(tpm_type, buffer, root_path=None, command_code=None, abort_on_error=True):
    """
    Generator.
    Take iterable which yields single bytes.
    Yield MarshalEvents.
    Return (command_code, remaining_bytes)
    command_code is an int or None.
    remaining_bytes is a generator or None if depleted.



    ErrorEvent: Parsing is aborted, if error_exceptions=True, an exception is raised
    WarningEvent: Parsing is continued, if warning_exceptions=True, an exception is raised


                                                    ..._exceptions=True                 Events

    invalid commandCode                             ValueConstraintViolatedError        ErrorEvent          + Forward
    done parsing before commandSize exhausted       SizeConstraintViolatedError         ErrorEvent          + Forward
    exhausted commandSize before done parsing       SizeConstraintViolatedError         ErrorEvent          + End (via surface from call stack via Exc)

    invalid selector                                ValueConstraintViolatedError        ErrorEvent          + Forward



    done parsing but input stream not exhausted     LeftoverBytesError if type is None  _ if type not None
    input stream exhausted but not done parsing     StreamExhaustedError                ErrorEvent (done)




    invalid value (not selector)                    ValueConstraintViolatedError        WarningEvent
    done parsing (part) before size exhausted       SizeConstraintViolatedError         WarningEvent (next struct OR ~~forward by rem size~~)
    (part) size exhausted before done parsing       SizeConstraintViolatedError         WarningEvent (continue parsing struct OR ~~next struct~~?)
    anticipate size exhaustion (part) size          SizeConstraintViolatedError         WarningEvent




    TODO in time order:
    done parsing
      commandSize exhausted
      input stream exhausted
    -> independent


    input stream exhausted
        done parsing (error)
        commandSize exhausted (ignored)


    commandSize exhausted
        done parsing (error if type is none, warning otherwise?)
        input stream exhausted  (?)

    """
    if root_path is None:
        root_path = Path(PathNode(PATH_NODE_ROOT_NAME))
    command_code_path = Path(root_path / PathNode("commandCode"))
    coroutine = process(
        tpm_type,
        path=root_path,
        command_code=command_code,
        abort_on_error=abort_on_error,
    )
    buffer_iter = iter(buffer)

    command_code = None
    byte = None
    is_bytes_remaining = True

    while is_bytes_remaining:
        # send next byte into coroutine
        try:
            event = coroutine.send(byte)
        except ConstraintViolatedError as error:
            # TODO code is redundant
            error.set_bytes_remaining(buffer_iter)
            raise error

        try:
            byte = next(buffer_iter)
        except StopIteration:
            is_bytes_remaining = False

        # get events from coroutine until None is yielded
        while event is not None:
            # TODO is this still needed?
            if isinstance(event, MarshalEvent) and event.path == command_code_path:
                command_code = event.value
            if not is_bytes_remaining and event.path == Path.from_string("."):
                # root path of new command/response although bytes are depleted
                # (occurs for CommandResponseStream), do not yield event and end parsing
                return command_code, None
            yield event
            try:
                event = coroutine.send(None)
            except StopIteration:
                if is_bytes_remaining:
                    # TODO properly make bytes_remaining a property for InputStreamBytesDepletedError, InputStreamSuperfluousBytesError
                    bytes_remaining = bytes(itertools.chain((byte,), buffer_iter))
                    raise InputStreamSuperfluousBytesError(
                        bytes_remaining=bytes_remaining, command_code=command_code
                    )
                else:
                    # all bytes were depleted
                    return command_code, None
            except ConstraintViolatedError as error:
                bytes_remaining = bytes(itertools.chain((byte,), buffer_iter))
                error.set_bytes_remaining(bytes_remaining)
                raise error

    raise InputStreamBytesDepletedError(command_code=command_code)


def process_primitive(tpm_type, path, size_constraints=None, abort_on_error=True):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    size = tpm_type._int_size
    data = []
    for _ in range(size):
        # before we consume byte, we need to check if we would violate any of the size constraints
        if size_constraints is not None:
            yield from size_constraints.bytes_parsed(
                path, 1, abort_on_error=abort_on_error
            )

        byte = yield None
        data.append(byte)
    value = int.from_bytes(data, byteorder="big")

    value_typed = tpm_type(value)
    event = MarshalEvent(path, tpm_type, value_typed)
    value_constraint = ValueConstraint(
        constraint_path=path, tpm_type=tpm_type, valid_values=value_typed._valid_values
    )
    if not value_typed.is_valid() and abort_on_error:
        raise ValueConstraintViolatedError(constraint=value_constraint, value=value)

    none = yield event
    assert none is None

    if not value_typed.is_valid() and not abort_on_error:
        none = yield WarningEvent(cause=event, constraint=None)
        assert none is None

    return size, value


def process_array(tpm_type, path, count, size_constraints=None, abort_on_error=True):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    assert len(tpm_type.__args__) == 1
    element_type = tpm_type.__args__[0]

    none = yield MarshalEvent(path, list[element_type], ...)
    assert none is None

    parent_path = path[:-1]
    element_size = 0
    for index in range(count):
        child_node = path[-1].with_index(index)
        element_size, _ = yield from process(
            element_type,
            parent_path / child_node,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    return element_size * count, None


def process_byte_sized_array(
    tpm_type, path, array_size_constraint, size_constraints=None, abort_on_error=True
):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    assert len(tpm_type.__args__) == 1
    element_type = tpm_type.__args__[0]

    none = yield MarshalEvent(path, list[element_type], ...)
    assert none is None

    parent_path = path[:-1]
    index = 0
    while array_size_constraint.size_already < array_size_constraint.size_max:
        child_node = path[-1].with_index(index)
        _element_size, _ = yield from process(
            element_type,
            parent_path / child_node,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
        index += 1

    array_size_constraint.assert_done()
    return array_size_constraint.size_already, None


def process_tpms(tpm_type, path, size_constraints=None, abort_on_error=True):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    size = 0
    values = {}
    element_size, element_value = None, None
    for field in fields(tpm_type):
        if is_list(field.type):
            # list member
            elements_size, _ = yield from process(
                field.type,
                path / PathNode(field.name),
                count=element_value,
                size_constraints=size_constraints,
                abort_on_error=abort_on_error,
            )
        elif hasattr(tpm_type, "_selectors") and field.name in tpm_type._selectors:
            # union member
            selector_name = tpm_type._selectors[field.name]
            selector_value = values[selector_name]
            element_size, element_value = yield from process(
                field.type,
                path / PathNode(field.name),
                selector=selector_value,
                size_constraints=size_constraints,
                abort_on_error=abort_on_error,
            )
        else:
            element_size, element_value = yield from process(
                field.type,
                path / PathNode(field.name),
                size_constraints=size_constraints,
                abort_on_error=abort_on_error,
            )
        values[field.name] = element_value
        size += element_size
    return size, None


def process_tpm2b(tpm_type, path, size_constraints=None, abort_on_error=True):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    # A dedicated funtion is needed because the size in TPM2B is always in bytes (not in elements)
    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    size_field, buffer_field = fields(tpm_type)
    size_path = path / PathNode(size_field.name)
    size_size, buffer_size_exp = yield from process(
        size_field.type,
        size_path,
        size_constraints=size_constraints,
        abort_on_error=abort_on_error,
    )
    # anticipate size constraint violation (e.g. commandSize) based on tpm2b size
    yield from size_constraints.bytes_parsed(
        size_path, buffer_size_exp, anticipate_only=True
    )

    if is_list(buffer_field.type):
        # common tpm2b with byte buffer
        buffer_size, _ = yield from process(
            buffer_field.type,
            path / PathNode(buffer_field.name),
            count=buffer_size_exp,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
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
            tpm2b_size_constraint = SizeConstraint(
                constraint_path=size_path, size_max=buffer_size_exp
            )
            size_constraints.append(tpm2b_size_constraint)

            buffer_size, _ = yield from process(
                buffer_field.type,
                path / PathNode(buffer_field.name),
                size_constraints=size_constraints,
                abort_on_error=abort_on_error,
            )

            tpm2b_size_constraint.assert_done()

    return size_size + buffer_size, None


def process_tpmu(tpm_type, path, selector, size_constraints=None, abort_on_error=True):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    none = yield MarshalEvent(path, tpm_type, ...)
    assert none is None

    # TODO _selected_by
    assert hasattr(
        tpm_type, "_selected_by"
    ), f"Union type {tpm_type} must have attribute ._selected_by"
    # reverse dict
    selection = {v: k for k, v in tpm_type._selected_by.items()}
    if selector in selection:
        selectee_name = selection[selector]
    elif None in selection:
        # use fallback option
        selectee_name = selection[None]
    else:
        # selector value fails to select union member
        # only possible if value checking is turnt off
        # TODO only possible if value checking is turnt off
        raise AssertionError(
            f"Selection error in {path} ({tpm_type.__name__}): {selector} not in {selection}. Value checking should have taken when parsing the selector, right?"
        )
        # raise ValueConstraintViolatedError(
        #     tpm_type=None,  # TODO type of selector
        #     path=None,  # TODO path of selector
        #     value=selector,
        #     selection=selection.keys(),
        # )

    field = next(f for f in fields(tpm_type) if f.name == selectee_name)
    if field.type is None:
        return 0, None
    if is_list(field.type):
        # union member of list type (must be statically sized as indicated in _list_size)
        assert hasattr(tpm_type, "_list_size")
        size, data = yield from process(
            field.type,
            path / PathNode(field.name),
            count=tpm_type._list_size[field.name],
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    else:
        size, data = yield from process(
            field.type,
            path / PathNode(field.name),
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )

    return size, data


def process_command(path, abort_on_error=True):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    tpm_type = Command
    command_size_constraint = SizeConstraint()
    authorization_area_constraint = SizeConstraint()
    size_constraints = SizeConstraintList((command_size_constraint,))

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

        # resolve Any type with _type_maps/_selectors
        # TODO change Any to any
        if field_type is Any:
            selector_name = tpm_type._selectors[field.name]
            selector_type = next(
                f.type for f in fields(tpm_type) if f.name == selector_name
            )
            types_map = tpm_type._type_maps[field.name]
            assert selector_name in values, f"Did not parse {selector_name} yet."
            selector_value = values[selector_name]
            try:
                field_type = types_map[selector_value]
            except KeyError as error:
                # it is ensured that every TPM_CC maps to a type in types_map
                # i.e. list(TPM_CC) is a subgroup of list(types_map.keys())
                value_constraint = ValueConstraint(
                    constraint_path=path + PathNode(selector_name),
                    tpm_type=selector_type,
                    valid_values=ValidValues(TPM_CC),
                )
                raise ValueConstraintViolatedError(
                    constraint=value_constraint,
                    value=selector_value,
                ) from error

        if field.name == "authorizationArea":
            element_size, element_value = yield from process(
                field_type,
                path / PathNode(field.name),
                array_size_constraint=authorization_area_constraint,
                size_constraints=size_constraints,
                abort_on_error=abort_on_error,
            )
            size += element_size

        if field.name == "commandSize":
            command_size_constraint.set_constraint(
                constraint_path=element_path, size_max=element_value
            )
        if field.name == "authSize":
            authorization_area_constraint.set_constraint(
                constraint_path=element_path, size_max=element_value
            )
            size_constraints.append(authorization_area_constraint)

        values[field.name] = element_value

    command_size_constraint.assert_done()
    size_constraints.assert_done()
    return size, values["commandCode"]


def process_response(path, command_code, abort_on_error=True):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    tpm_type = Response
    response_size_constraint = SizeConstraint()
    parameter_size_constraint = SizeConstraint()
    size_constraints = SizeConstraintList((response_size_constraint,))

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
            try:
                field_type = types_map[command_code]
            except KeyError as error:
                # it is ensured that every TPM_CC maps to a type in types_map
                # i.e. list(TPM_CC) is a subgroup of list(types_map.keys())
                # TODO
                value_constraint = ValueConstraint(
                    constraint_path=path + PathNode(selector_name),
                    tpm_type=selector_type,
                    valid_values=ValidValues(TPM_CC),
                )
                raise ValueConstraintViolatedError(
                    constraint=value_constraint,
                    value=command_code,
                ) from error

        if field.name == "authorizationArea":
            # authorizationArea is a list with 1-n elements (remaining bytes)
            element_size, element_value = yield from process(
                field_type,
                path / PathNode(field.name),
                array_size_constraint=response_size_constraint,
                size_constraints=size_constraints,
                abort_on_error=abort_on_error,
            )
            size += element_size
        else:
            # all other members
            element_path = path / PathNode(field.name)
            element_size, element_value = yield from process(
                field_type,
                element_path,
                size_constraints=size_constraints,
                abort_on_error=abort_on_error,
            )
            size += element_size

            if field.name == "parameters" and "parameterSize" in values:
                parameter_size_constraint.assert_done()

        if field.name == "responseSize":
            response_size_constraint.set_constraint(
                constraint_path=element_path, size_max=element_value
            )
        if field.name == "parameterSize":
            parameter_size_constraint.set_constraint(
                constraint_path=element_path, size_max=element_value
            )
            size_constraints.append(parameter_size_constraint)

        values[field.name] = element_value

    response_size_constraint.assert_done()
    size_constraints.assert_done()
    return size, None


def process_command_response_stream(path, abort_on_error=True):
    """Generator. Take iterable which yields single bytes. Yield MarshalEvents."""
    while True:
        # The calling function must detect when this generator is done. Basically, when there are no bytes left and this
        # generator yields the command/response root event for the new command/response, we are done here. This cannot
        # be handles at this level. Well, technically it can, but trust me, it is not something anyone would want...
        _, command_code = yield from process(
            Command, path, abort_on_error=abort_on_error
        )
        _, _ = yield from process(
            Response, path, command_code=command_code, abort_on_error=abort_on_error
        )


def process(
    tpm_type,
    path,
    selector=None,
    count=None,
    command_code=None,
    array_size_constraint=None,
    size_constraints=None,
    abort_on_error=True,
):
    """Coroutine. Send in one byte if it yields None. Send in None if it yields an MarshalEvents."""
    if size_constraints is None:
        size_constraints = SizeConstraintList()

    if tpm_type is CommandResponseStream:
        result = yield from process_command_response_stream(
            path, abort_on_error=abort_on_error
        )
    elif tpm_type is Command:
        result = yield from process_command(path, abort_on_error=abort_on_error)
    elif tpm_type is Response:
        result = yield from process_response(
            path, command_code=command_code, abort_on_error=abort_on_error
        )
    elif hasattr(tpm_type, "_int_size"):
        # Primitives, TPMA
        result = yield from process_primitive(
            tpm_type,
            path,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    elif tpm_type.__name__.startswith("TPM2B"):
        result = yield from process_tpm2b(
            tpm_type,
            path,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    elif hasattr(tpm_type, "_selected_by"):
        # TPMU
        result = yield from process_tpmu(
            tpm_type,
            path,
            selector=selector,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    elif is_list(tpm_type) and array_size_constraint is not None:
        # list[...] with size in bytes
        result = yield from process_byte_sized_array(
            tpm_type,
            path,
            array_size_constraint=array_size_constraint,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    elif is_list(tpm_type):
        # list[...] with count of elements
        result = yield from process_array(
            tpm_type,
            path,
            count=count,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    else:
        # TPMS, TPMT, TPML
        result = yield from process_tpms(
            tpm_type,
            path,
            size_constraints=size_constraints,
            abort_on_error=abort_on_error,
        )
    return result
