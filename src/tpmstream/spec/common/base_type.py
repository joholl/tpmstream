def numeric(cls):
    """
    Emulate an int type. Bases behavior on <instance>.__int__() or, if not implemented, <instance>._value.
    """
    if not hasattr(cls, "__int__"):

        def __int__(self):
            # cast to int to enable a @numeric as self._value
            return int(self._value)

        setattr(cls, "__int__", __int__)

    def __index__(self):
        return int(self._value)

    setattr(cls, "__index__", __index__)

    def __add__(self, other):
        return int(self) + other

    setattr(cls, "__add__", __add__)

    def __radd__(self, other):
        return other + int(self)

    setattr(cls, "__radd__", __radd__)

    def __sub__(self, other):
        return int(self) - other

    setattr(cls, "__sub__", __sub__)

    def __rsub__(self, other):
        return other - int(self)

    setattr(cls, "__rsub__", __rsub__)

    def __mul__(self, other):
        return int(self) * other

    setattr(cls, "__mul__", __mul__)

    def __rmul__(self, other):
        return other * int(self)

    setattr(cls, "__rmul__", __rmul__)

    def __truediv__(self, other):
        return int(self) / other

    setattr(cls, "__truediv__", __truediv__)

    def __rtruediv__(self, other):
        return other / int(self)

    setattr(cls, "__rtruediv__", __rtruediv__)

    def __floordiv__(self, other):
        return int(self) // other

    setattr(cls, "__floordiv__", __floordiv__)

    def __rfloordiv__(self, other):
        return other // int(self)

    setattr(cls, "__rfloordiv__", __rfloordiv__)

    def __mod__(self, other):
        return int(self) % other

    setattr(cls, "__mod__", __mod__)

    def __rmod__(self, other):
        return other % int(self)

    setattr(cls, "__rmod__", __rmod__)

    def __divmod__(self, other):
        return int(self) // other, int(self) % other

    setattr(cls, "__divmod__", __divmod__)

    def __rdivmod__(self, other):
        return other // int(self), other % int(self)

    setattr(cls, "__rdivmod__", __rdivmod__)

    def __pow__(self, other):
        return int(self) ** other

    setattr(cls, "__pow__", __pow__)

    def __rpow__(self, other):
        return other ** int(self)

    setattr(cls, "__rpow__", __rpow__)

    def __lshift__(self, other):
        return int(self) << other

    setattr(cls, "__lshift__", __lshift__)

    def __rlshift__(self, other):
        return other << int(self)

    setattr(cls, "__rlshift__", __rlshift__)

    def __rshift__(self, other):
        return int(self) >> other

    setattr(cls, "__rshift__", __rshift__)

    def __rrshift__(self, other):
        return other >> int(self)

    setattr(cls, "__rrshift__", __rrshift__)

    def __and__(self, other):
        return int(self) & other

    setattr(cls, "__and__", __and__)

    def __rand__(self, other):
        return other & int(self)

    setattr(cls, "__rand__", __rand__)

    def __xor__(self, other):
        return int(self) ^ other

    setattr(cls, "__xor__", __xor__)

    def __rxor__(self, other):
        return other ^ int(self)

    setattr(cls, "__rxor__", __rxor__)

    def __or__(self, other):
        return int(self) | other

    setattr(cls, "__or__", __or__)

    def __ror__(self, other):
        return other | int(self)

    setattr(cls, "__ror__", __ror__)

    def __lt__(self, other):
        return int(self) < other

    setattr(cls, "__lt__", __lt__)

    def __le__(self, other):
        return int(self) <= other

    setattr(cls, "__le__", __le__)

    def __eq__(self, other):
        return int(self) == other

    setattr(cls, "__eq__", __eq__)

    def __ne__(self, other):
        return int(self) != other

    setattr(cls, "__ne__", __ne__)

    def __gt__(self, other):
        return int(self) > other

    setattr(cls, "__gt__", __gt__)

    def __ge__(self, other):
        return int(self) >= other

    setattr(cls, "__ge__", __ge__)

    def __hash__(self):
        return hash(int(self))

    setattr(cls, "__hash__", __hash__)

    def __str__(self):
        return str(int(self))

    setattr(cls, "__str__", __str__)

    def __repr__(self):
        return f"{type(self).__name__}({str(self)})"

    setattr(cls, "__repr__", __repr__)

    return cls


@numeric
class _INT:
    _signed = True

    def __init__(self, value: int = None):
        instance = self._valid_values.get(value)
        if instance is not None:
            self._value = instance
        else:
            self._value = value

    def is_valid(self):
        return self._value in self._valid_values

    def to_bytes(self, size=None, byteorder="big", signed=None):
        if size is None:
            size = self._int_size
        if signed is None:
            signed = self._signed
        return self._value.to_bytes(size, byteorder=byteorder, signed=signed)

    def __format__(self, format_spec):
        return self._value.__format__(format_spec)

    def __str__(self):
        return str(self._value)

    @classmethod
    def plus(cls):
        # TODO implement
        return cls


class _UINT(_INT):
    _signed = False
