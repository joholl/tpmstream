from tpmstream.common.error import (
    ConstraintObsoleteError,
    SizeConstraintExceededError,
    SizeConstraintSubceededError,
)
from tpmstream.common.path import Path
from tpmstream.spec.common.values import ValidValues


def implies(a: bool, b: bool):
    return not a or b


def consume_bytes(count):
    for _ in range(count):
        _ = yield


class Constraint:
    def __init__(self, constraint_path: Path = None):
        self.constraint_path = constraint_path


class ValueConstraint(Constraint):
    def __init__(self, constraint_path: Path, tpm_type, valid_values: ValidValues):
        super().__init__(constraint_path=constraint_path)
        self.tpm_type = tpm_type
        self.valid_values = valid_values


class SizeConstraint(Constraint):
    def __init__(
        self, constraint_path: Path = None, size_max: int = None, size_already: int = 0
    ):
        super().__init__(constraint_path=constraint_path)
        assert implies(
            constraint_path is None, size_max is None
        ), "If constraint_path is None, size_max must be None, too"
        self.size_already = size_already
        self.size_max = size_max
        self.is_obsolete = False

    def set_constraint(self, constraint_path: Path, size_max: int):
        self.constraint_path = constraint_path
        self.size_max = size_max

    def bytes_parsed(self, path, size, anticipate_only=False):
        """Add to the size of parsed bytes."""
        if self.is_obsolete:
            raise ConstraintObsoleteError()

        # look ahead (so self.size_already is the number of parsed bytes)
        if self.size_max is not None and self.size_already + size > self.size_max:
            yield from consume_bytes(self.size_max - self.size_already)
            raise SizeConstraintExceededError(
                self,
                violator_path=path,
                exceeded_by=self.size_already + size - self.size_max,
            )

        if not anticipate_only:
            self.size_already += size

        return
        yield

    def assert_done(self):
        assert (
            self.size_max is not None
        ), "Cannot assert the end of a constraint before having initialized it."

        if self.size_already != self.size_max:
            raise SizeConstraintSubceededError(self)

        self.is_obsolete = True

    def __repr__(self):
        return f"{type(self).__name__}({self.constraint_path}: {self.size_already}/{self.size_max})"


class SizeConstraintList(list[SizeConstraint]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def bytes_parsed(self, path, size, anticipate_only=False):
        # TODO always in order from deepest to highest
        for constraint in self.copy():
            try:
                yield from constraint.bytes_parsed(
                    path,
                    size,
                    anticipate_only=anticipate_only,
                )
            except ConstraintObsoleteError:
                self.remove(constraint)

    def assert_done(self):
        # if not all constraints are obsolete by now, this is a bug
        assert all(constraint.is_obsolete for constraint in self)
