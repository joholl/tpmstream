from dataclasses import dataclass

from tpmstream.common.error import ConstraintViolatedError
from tpmstream.common.path import Path


class Event:
    pass


@dataclass(frozen=True)
class MarshalEvent(Event):
    """Type is tracked because list[...] looses element type once instantiated."""

    path: Path
    type: type
    value: int = None

    def __str__(self):
        value = "..." if self.value is ... else self.value
        return f"{self.path} = {value}"


@dataclass(frozen=True)
class InfoEvent(Event):
    error: ConstraintViolatedError

    def __str__(self):
        return f"Warning: {self.error}"


@dataclass(frozen=True)
class WarningEvent(InfoEvent):
    pass


@dataclass(frozen=True)
class ErrorEvent(InfoEvent):
    pass
