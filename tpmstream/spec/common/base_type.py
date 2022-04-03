class _INT:
    def __init__(self, value: int = None):
        self._value = value
        if hasattr(self, "_valid_values"):
            enum_value = self._valid_values.get(value)
            if enum_value is not None:
                self._value = enum_value

    def __lt__(self, other):
        return self._value < other

    def __le__(self, other):
        return self._value <= other

    def __eq__(self, other):
        return self._value == other

    def __ne__(self, other):
        return self._value != other

    def __gt__(self, other):
        return self._value > other

    def __ge__(self, other):
        return self._value >= other

    def __hash__(self):
        return hash(self._value)

    # TODO this instead of explicit
    # def __getattr__(self, name):
    #     return getattr(self._value, name)

    def __int__(self, other):
        return self._value

    def to_bytes(self, size=None, byteorder="big"):
        if size is None:
            size = self._int_size
        # TODO WHAT NOW!? TPMI_ST_COMMAND_TAG (_INT) has TPM_ST (_INT)?
        return self._value.to_bytes(self._int_size, byteorder)

    def __format__(self, format_spec):
        return self._value.__format__(format_spec)

    def __str__(self):
        return str(self._value)

    @classmethod
    def plus(cls):
        # TODO implement
        return cls
