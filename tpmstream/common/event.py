from dataclasses import dataclass, fields
from typing import Any

from tpmstream.common.util import is_list
from tpmstream.spec.commands.commands import Command
from tpmstream.spec.commands.responses import Response

PATH_NODE_ROOT_NAME = ""


@dataclass(frozen=True)
class PathNode:
    """index is applicable to list nodes, only."""

    name: str
    index: int = None

    def __str__(self):
        if self.index is None:
            return self.name
        return f"{self.name}[{self.index}]"


class Path(tuple[PathNode]):
    def __new__(cls, obj=None):
        if obj is None:
            return super().__new__(cls)

        if hasattr(obj, "__iter__"):
            return super().__new__(cls, obj)

        return super().__new__(cls, (obj,))

    def __add__(self, other):
        try:
            return Path(super().__add__(other))
        except TypeError:
            return self.__add__((other,))

    def __truediv__(self, other):
        return self.__add__(other)

    def __getitem__(self, key):
        result = super().__getitem__(key)
        if isinstance(result, tuple):
            return Path(result)
        return result

    def __repr__(self):
        return ".".join(f"{node}" for node in self)

    def __str__(self):
        return repr(self)


@dataclass(frozen=True)
class MarshalEvent:
    """Type is tracked because list[...] looses element type once instantiated."""

    path: Path
    type: type
    value: int = None

    def __str__(self):
        value = "..." if self.value is ... else self.value
        return f"{self.path} = {value}"


def separate_events(events):
    """Takes generator of events. Yield lists of events, each is one command or response."""
    events_single_command_or_response = []
    for event in iter(events):
        if event.path == ROOT_PATH and events_single_command_or_response != []:
            yield events_single_command_or_response
            events_single_command_or_response = []
        events_single_command_or_response.append(event)
    if events_single_command_or_response != []:
        yield events_single_command_or_response


def events_to_objs(events: list[MarshalEvent]):
    """Takes iterable of events and yields python objects of type tpm_type."""
    events_single_cmd_rsp = separate_events(events)

    command_code = None
    for events in events_single_cmd_rsp:
        if command_code is None:
            command = events_to_obj(Command, events)
            command_code = command.commandCode
            yield command
        else:
            response = events_to_obj(Response, events, command_code=command_code)
            yield response
            command_code = None


def _events_to_dict(events: list[MarshalEvent]):
    """List of events, a path (where paths are tuples of strings) and a value to a nested tuple."""

    def list_setdefault(list: list, index: int, elem: any):
        """Like list.insert(), but fillcs list with None if too small. Returns elem."""
        if index < len(list) + 1:
            placeholders = index - len(list) + 1
            list.extend([None] * placeholders)
        if list[index] is not None:
            return list[index]
        list[index] = elem
        return elem

    root = {}
    for event in events:
        # traverse path ("directories" = nodes)
        node = root
        for i, next_node in enumerate(event.path):
            if i < len(event.path) - 1:
                next_node_value = {}
            else:
                # leaf node
                if event.value is ...:
                    next_node_value = [] if is_list(event.type) else {}
                else:
                    next_node_value = event.value

            if next_node.index is None:
                node = node.setdefault(next_node.name, next_node_value)
            else:
                # list: insert at index
                if next_node.name not in node:
                    node[next_node.name] = []
                node = list_setdefault(
                    node[next_node.name], next_node.index, next_node_value
                )
    return root


def _list_to_obj(tpm_type, list_obj: list[any]):
    """Turns list (in nested dict structure) into a list of python objects. tpm_type is list[<some tpm type>]."""
    assert len(tpm_type.__args__) == 1
    elem_type = tpm_type.__args__[0]
    if isinstance(list_obj, bytes):
        return list_obj
    return [
        _to_obj(elem_type, e) for e in list_obj
    ]  # TODO typed list? :list[...] or list[...]()


def _dict_to_obj(tpm_type, dict_obj: dict[str, any], command_code=None):
    """Turns nested dict into an object of type tpm_type."""
    if tpm_type is Command:
        command_code = dict_obj["commandCode"]

    def get_attr_type(name: str):
        try:
            result_type = next(f for f in fields(tpm_type) if f.name == name).type
        except TypeError as e:
            raise TypeError(
                f"Could not find member .{name} in type {tpm_type} via dataclass.fields() lookup."
            ) from e
        if result_type is Any:
            if hasattr(tpm_type, "_selectors"):
                # Command
                selector_name = tpm_type._selectors[name]
                selector_value = dict_obj[selector_name]
            else:
                # Response
                selector_value = command_code
            type_map = tpm_type._type_maps[name]
            result_type = type_map[selector_value]
        return result_type

    kwargs = {k: _to_obj(get_attr_type(k), v) for k, v in dict_obj.items()}
    return tpm_type(**kwargs)


def _to_obj(tpm_type, value, command_code=None):
    """If value is dict, tpm_type is the type it should be converted to."""
    if isinstance(value, dict):
        return _dict_to_obj(tpm_type, value, command_code=command_code)
    elif isinstance(value, list):
        return _list_to_obj(tpm_type, value)
    else:
        return value


def events_to_obj(tpm_type, events: list[MarshalEvent], command_code=None):
    """Takes iterable of events and returns python object of type tpm_type."""
    # Turn events into dict. If events is a generator, it will be depleted.
    obj_dict = _events_to_dict(events)
    return _to_obj(tpm_type, obj_dict[PATH_NODE_ROOT_NAME], command_code=command_code)


def obj_to_events(obj, path=None) -> list[MarshalEvent]:
    """Takes obj and returns a generator of events."""
    if path is None:
        path = Path(PathNode(PATH_NODE_ROOT_NAME))
    try:
        # dataclass type
        obj_fields = fields(obj)
    except TypeError:
        if isinstance(obj, list):
            # list node
            parent_path = path[:-1]
            elem_name = path[-1].name
            for i, elem in enumerate(obj):
                # yield all child elements
                yield from obj_to_events(
                    obj=elem, path=parent_path / PathNode(name=elem_name, index=i)
                )
        else:
            # leaf node
            yield MarshalEvent(path, type(obj), obj)
        return

    # yield struct parent
    yield MarshalEvent(path, type(obj), ...)  # TODO align

    # for all fields in dataclass
    for field in obj_fields:
        if getattr(obj, field.name) is None:
            continue

        if is_list(field.type):
            # yield list "parent"
            yield MarshalEvent(path / PathNode(field.name), field.type, ...)
        yield from obj_to_events(
            obj=getattr(obj, field.name), path=path / PathNode(field.name)
        )


# for comparison only
ROOT_PATH = Path(PathNode(PATH_NODE_ROOT_NAME))
