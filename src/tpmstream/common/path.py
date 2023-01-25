from dataclasses import dataclass

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

    def with_index(self, index):
        return PathNode(name=self.name, index=index)


class Path(tuple[PathNode]):
    sep = "."

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
        return Path.sep.join(f"{node}" for node in self)

    def __str__(self):
        return repr(self)

    @classmethod
    def from_string(cls, string: str):
        nodes_strings = string.split(Path.sep)
        if nodes_strings[-1] == "":
            # string ends with ".", ignore it (or go with root path if string is just ".")
            nodes_strings = nodes_strings[:-1]
        return cls(PathNode(s) for s in nodes_strings)


# for comparison only
ROOT_PATH = Path(PathNode(PATH_NODE_ROOT_NAME))
