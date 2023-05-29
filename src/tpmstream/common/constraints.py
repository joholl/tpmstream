from __future__ import annotations

from tpmstream.common.error import (
    AnticipatedSizeConstraintExceededError,
    ConstraintObsoleteError,
    SizeConstraintExceededError,
    SizeConstraintSubceededError,
)
from tpmstream.common.event import WarningEvent
from tpmstream.common.path import Path
from tpmstream.spec.common.values import ValidValues


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
    def __init__(self, size_already: int = 0):
        """
        Constraint must be set with set_constraint(), because we might need to yield events.
        """
        super().__init__(constraint_path=None)
        self.size_already = size_already
        self.is_obsolete = False
        self.size_max = None

    def set_constraint(
        self,
        constraint_path: Path,
        size_max: int,
        other_size_constraints: SizeConstraintList,
        abort_on_error,
    ):
        """
        Anticipates, if any of other_size_constraints will be violated.
        other_size_constraints are only checked at set_constraint()-time.
        """
        assert constraint_path is not None
        assert size_max >= 0
        assert hasattr(other_size_constraints, "bytes_parsed")

        self.constraint_path = constraint_path
        self.size_max = size_max

        # for commandSize and responseSize, the self might be in other_size_constraint. Exlclude.
        other_size_constraints = SizeConstraintList(
            c for c in other_size_constraints if c != self
        )

        # anticipate size constraint violation of already existing size constraints (e.g. commandSize)
        try:
            yield from other_size_constraints.bytes_parsed(
                self.constraint_path,
                self.size_max,
                anticipate_only=True,
            )
        except AnticipatedSizeConstraintExceededError as error:
            if abort_on_error:
                raise error
            yield WarningEvent(error=error)

    def bytes_parsed(self, path, size, anticipate_only=False):
        """Add to the size of parsed bytes."""
        if self.is_obsolete:
            raise ConstraintObsoleteError()

        # look ahead (so self.size_already is the number of parsed bytes)
        if self.size_max is not None and self.size_already + size > self.size_max:
            if anticipate_only:
                raise AnticipatedSizeConstraintExceededError(
                    self,
                    violator_path=path,
                    violator_value=size,
                    exceeded_by=self.size_already + size - self.size_max,
                )
            else:
                self.is_obsolete = True
                yield from consume_bytes(self.size_max - self.size_already)
                raise SizeConstraintExceededError(
                    self,
                    violator_path=path,
                    exceeded_by=self.size_already + size - self.size_max,
                )

        if not anticipate_only:
            self.size_already += size

    def assert_done(
        self, all_size_constraints: SizeConstraintList, abort_on_error=True
    ):
        assert (
            self.size_max is not None
        ), "Cannot assert the end of a constraint before having initialized it."

        # finalize self and remove it from constraint list
        self.is_obsolete = True

        if self.size_already == self.size_max:
            return

        # we parsed fewer bytes than anticipated
        error = SizeConstraintSubceededError(self)
        if abort_on_error:
            raise error
        yield WarningEvent(error=error)

        yield from consume_bytes(self.size_max - self.size_already)

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
