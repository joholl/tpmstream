from dataclasses import dataclass

from ...common.event import Path


def implies(a: bool, b: bool):
    return not a or b


class ConstraintViolated(Exception):
    pass


class ValueConstraintViolated(ConstraintViolated):
    pass


class SizeConstraintViolated(ConstraintViolated):
    def __init__(self, a, b=None, c=None):
        """Arg is either a string (error message) or a path and two ints (size_max, size_already)."""
        if isinstance(a, str):
            assert (
                a is None and b is None
            ), "If first argument is a string, no other arguments can be given."
            super().__init__(a)
        else:
            # TODO though which path? pass through add_size() and SizeConstraintViolated()
            super().__init__(
                f"Violated size constraint: {a} = {b} but parsed {c} bytes"
            )


class SizeConstraint:
    def __init__(
        self, constraint_path: Path = None, size_max: int = None, size_already: int = 0
    ):
        assert implies(
            constraint_path is None, size_max is None
        ), "If constraint_path is None, size_max must be None, too"
        self.constraint_path = constraint_path
        self.size_already = size_already
        self.size_max = size_max
        self.invalidated = False

    def set_constraint(self, constraint_path: Path, size_max: int):
        self.constraint_path = constraint_path
        self.size_max = size_max

    def bytes_parsed(self, size):
        """Add to the size of parsed bytes."""
        assert (
            not self.invalidated
        ), "This constraint has been invalidated already, cannot track new bytes"

        self.size_already += size

        if self.size_max is not None and self.size_already > self.size_max:
            raise SizeConstraintViolated(
                self.constraint_path, self.size_max, self.size_already
            )

    def __isub__(self, other):
        self.bytes_parsed(other)
        return self

    def assert_done(self):
        if self.size_already != self.size_max:
            raise SizeConstraintViolated(
                self.constraint_path, self.size_max, self.size_already
            )

        self.invalidated = True


class SizeConstraintList(list[SizeConstraint]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def bytes_parsed(self, size):
        for constraint in self:
            constraint.bytes_parsed(size)
