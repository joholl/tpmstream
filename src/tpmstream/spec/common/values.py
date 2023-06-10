# class Range:
#     pass
import inspect
from dataclasses import dataclass
from math import ceil


class ValidValues:
    def __init__(self, *values):
        self._values = values

    def __contains__(self, value):
        return self.get(value) is not None

    def get(self, value):
        for v in self._values:
            if hasattr(v, "__contains__") and value in v:
                if isinstance(v, range):
                    if value not in v:
                        raise ValueError(f"{value} not in {v}")
                    return value
                elif isinstance(v, NamedRange):
                    return v.by_number(value)
                else:
                    # enum type
                    return v(value)
            if value == v:
                return v
        return None

    def __iter__(self):
        for v in self._values:
            # range, NamedRange or enum type
            if hasattr(v, "__iter__"):
                yield from v
            else:
                yield v

    def __repr__(self):
        args_str = ", ".join(f"{v}" for v in self._values)
        return f"{type(self).__name__}({args_str})"


@dataclass
class NamedRange:
    def __init__(self, type, basename, a, b=None, sep=".", index_nibbles=None):
        """Size is int size in bytes. Like range. End is exclusive."""
        self._type = type
        self._basename = basename
        if b is None:
            self._start = 0
            self._end = a
        else:
            self._start = a
            self._end = b
        self._sep = sep
        if index_nibbles is None:
            index_nibbles = ceil((self._end - self._start - 1).bit_length() / 4.0)
        self._index_nibbles = index_nibbles

    def __contains__(self, item):
        return self._start <= item < self._end

    def __iter__(self):
        yield from (self.by_number(i) for i in range(self._start, self._end))

    def __repr__(self):
        return f"{type(self).__name__}({self._type.__name__}, {self._basename}, {self._start}, {self._end})"

    def by_number(self, number):
        if not self._start <= number < self._end:
            return ValueError(
                f"{number:x} is not in range({self._start:0}, {self._end:0})"
            )

        name = "{basename}{sep}{index:0{nibbles}x}".format(
            basename=self._basename,
            sep=self._sep,
            # TODO cast should not be necessary, but python does not call number.__sub__()
            index=int(number) - self._start,
            nibbles=self._index_nibbles,
        )
        return self._type(value=number, name=name)

    def by_name(self, name):
        basename = self._sep.join(name.split(self._sep)[:-1])
        if not basename == self._basename:
            raise ValueError(
                f"Expected basename {self._basename} but basename of {name} is {basename}"
            )
        index_str = name.split(self._sep)[-1]
        number = self._start + int(index_str, 16)
        return self._type(value=number, name=name)


def _is_public_non_funtion_attr(name: str, attr: any) -> list[tuple[str, any]]:
    """Utility function for getting the "interesting" attributes."""
    return not inspect.isroutine(attr) and not name.startswith("_")


def tpm_bitfield(replace_format=True):
    def decorator(cls):
        """"""
        # class IterableMeta(type):
        #     def __iter__(self):
        #         return self.attributes()
        # cls = IterableMeta(cls.__name__, cls.__bases__, dict(cls.__dict__))

        def attributes(self):
            """Iterator for all public non-function attributes."""
            maks_generator = (
                attr
                for name, attr in inspect.getmembers(type(self))
                if _is_public_non_funtion_attr(name, attr)
            )
            return sorted(maks_generator, key=lambda mask: mask._value)

        if not hasattr(cls, "attributes"):
            setattr(cls, "attributes", attributes)

        # add __init__ function (similar to the __init__ function of IntEnum)
        def __init__(self, value, name=None, details=None):
            if name is not None:
                # single mask (class attribute)
                self._name = name
                self._value = value
            else:
                # runtime instance (usually multiple masks combined)
                self._name = None
                self._value = value
            self._details = details

        setattr(cls, "__init__", __init__)

        def __format__(self, _format_spec=None):
            if self._name is not None:
                # pure bit (class attribute)
                return f"{type(self).__name__}.{self._name}"

            return " | ".join(
                f"{b}" for b in self.attributes() if getattr(self, b._name)
            )

        if replace_format:
            setattr(
                cls, "__format__", __format__
            )  # lambda self, *args: self._value.__format__(*args))
            setattr(cls, "__str__", __format__)
            setattr(cls, "__repr__", __format__)

        # TODO delegate functions to value (__getattribute__?)
        # def __getattr__(self, name):
        #     return getattr(self._value, name)
        # attrs["__getattr__"] = __getattr__

        # TODO implement int operators, e.g. +, |

        # replace attributes with instances of cls, delete those for which filter is falsy
        for attr_name, attr_value in inspect.getmembers(cls):
            if not _is_public_non_funtion_attr(attr_name, attr_value):
                continue

            class Bit:
                def __init__(self, name, mask):
                    self._name = name
                    self._mask = mask

                def __get__(self, obj, objtype=None):
                    if obj is None:
                        # called on class
                        bits = self._mask
                    else:
                        # called on instance
                        bits = obj._value & self._mask
                        mask = self._mask
                        while mask & 0x1 == 0x0:
                            bits >>= 1
                            mask >>= 1
                        return bits  # TODO ?

                    return cls(value=bits, name=self._name)

            setattr(cls, attr_name, Bit(name=attr_name, mask=attr_value))

        return cls

    return decorator


def tpm_enum(*args, filter=None):
    def _tpm_enum(cls):
        """
        Creates a enum-like class for TPM types. Unike python enums, a tpm_enum can have unknown values. Additionally,
        not only discrete values can be specified, but also valid value ranges.

        TODO more info on how to do it.

        TODO filter for AlgType, (decorator with params)
        """

        class IterableMeta(type):
            def __iter__(self):
                return self.class_iter()

            def __contains__(self, obj):
                return self.class_contains(obj)

            def __str__(self):
                return self.__name__

        cls = IterableMeta(cls.__name__, cls.__bases__, dict(cls.__dict__))

        @classmethod
        def class_iter(cls):
            """Iterator for all public non-function attributes."""
            return (
                attr
                for name, attr in inspect.getmembers(cls)
                if _is_public_non_funtion_attr(name, attr)
            )

        setattr(cls, "class_iter", class_iter)

        @classmethod
        def class_contains(cls, value):
            """Iterator for all public non-function attributes."""
            return any(
                value == attr or (hasattr(attr, "__contains__") and value in attr)
                for attr in cls
            )

        setattr(cls, "class_contains", class_contains)

        @classmethod
        def _filter(cls, filter):
            """Returns new type with filtered enum values. Filter function takes name, attr."""
            return tpm_enum(filter=filter)(cls)

        setattr(cls, "filter", _filter)

        @classmethod
        def plus(cls):
            # TODO is this needed? if so, implement (see tpm_dataclass)
            return cls

        setattr(cls, "plus", plus)

        @classmethod
        def by_value(cls, value):
            for attr in cls:
                if isinstance(attr, NamedRange) and value in attr:
                    return attr.by_number(value)
                elif attr == value:
                    return attr
            raise ValueError()

        setattr(cls, "by_value", by_value)

        # add __init__ function (similar to the __init__ function of IntEnum)
        def __init__(self, value, name=None):
            # TODO refactor
            if name is not None:
                # name is known, do not look it up (initial instantiation)
                self._name = name
                self._value = value
            else:
                # name is not known, look it up (normal instantiation)
                try:
                    instance = type(self).by_value(value)
                    self._name = instance._name
                    self._value = instance._value
                except ValueError:
                    # value is unknown
                    self._name = None
                    self._value = value

        setattr(cls, "__init__", __init__)

        def __format__(self, _format_spec=None):
            return f"{type(self).__name__}.{self._name}"

        setattr(cls, "__format__", __format__)
        setattr(cls, "__str__", __format__)
        setattr(cls, "__repr__", __format__)

        setattr(cls, "_valid_values", ValidValues(cls))

        # TODO recursion error
        # def __getattr__(self, name):
        #     return getattr(self._value, name)
        # setattr(cls, "__getattr__", __getattr__)

        # replace attributes with instances of cls, delete those for which filter is falsy
        for attr_name, attr_value in inspect.getmembers(cls):
            if not _is_public_non_funtion_attr(attr_name, attr_value):
                continue

            if filter is not None and not filter(attr_name, attr_value):
                delattr(cls, attr_name)
                # TODO ? del cls.__annotations__[attr_name]
                continue
            elif isinstance(attr_value, range):
                attr_wrap = NamedRange(
                    cls, attr_name, attr_value.start, attr_value.stop
                )
            else:
                attr_wrap = cls(value=attr_value, name=attr_name)
            setattr(cls, attr_name, attr_wrap)

        return cls

    if len(args) == 1 and callable(args[0]):
        # No arguments, this is the decorator
        return _tpm_enum(args[0])
    else:
        # This is just returning the decorator
        return _tpm_enum


def tpm_dataclass(cls):
    """
    A dataclass for TPM types (TPMS, TPMT, TPML, TPMU, TPM2B) based on the python dataclasses. Creates an immutable
    dataclass where all fields can be None at instantiation time.

    TODO more info on how to do it.

    TODO Fields of type Optional[] will not be accessible. Calling <dataclass>.plus() yields a derived type for which
         these fields can be accessed.
    """

    # set all fields to None to make them optional for dataclass
    if hasattr(cls, "__annotations__"):
        for attr_name, attr_type in cls.__annotations__.items():
            if not hasattr(cls, attr_name):
                setattr(cls, attr_name, None)

    # create dataclass
    result = dataclass(cls, frozen=True)

    # add plus variant (which includes optional fields)
    def plus():
        # TODO with optional fields
        return result

    # TODO maybe set that only if there are optional types
    setattr(result, "plus", plus)
    return result
