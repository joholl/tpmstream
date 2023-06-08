import binascii


class InputStreamDepletedSignal(Exception):
    pass


class InputStreamBytesDepletedError(Exception):
    def __init__(self, command_code=None):
        super().__init__("Input stream exhausted but parser is not done.")
        self.command_code = command_code


class InputStreamSuperfluousBytesError(Exception):
    def __init__(self, bytes_remaining=None, command_code=None):
        bytes_remaining = bytes(bytes_remaining)
        super().__init__(
            f"Parser done but input stream not exhausted. Remaining bytes: {binascii.hexlify(bytes_remaining).decode()}"
        )
        self.bytes_remaining = bytes_remaining
        self.command_code = command_code


class ConstraintObsoleteError(Exception):
    pass


class ConstraintViolatedError(Exception):
    def __init__(self, *args, bytes_remaining=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bytes_remaining = bytes_remaining

    def set_bytes_remaining(self, bytes):
        self.bytes_remaining = bytes


class ValueConstraintViolatedError(ConstraintViolatedError):
    def __init__(self, constraint, value, **kwargs):
        super().__init__(
            f"Parsed bad value for {constraint.tpm_type.__name__} {constraint.constraint_path} = 0x{int(value):x} = {int(value)} not in {constraint.valid_values}",
            **kwargs,
        )
        self.constraint = constraint
        self.value = value


class SizeConstraintViolatedError(ConstraintViolatedError):
    def __init__(self, message, constraint, **kwargs):
        super().__init__(message, **kwargs)
        self.constraint = constraint


class SizeConstraintExceededError(SizeConstraintViolatedError):
    def __init__(self, constraint, violator_path, exceeded_by, **kwargs):
        super().__init__(
            f"Violated size constraint {constraint.constraint_path} = {constraint.size_max}: already parsed {constraint.size_already} bytes and {violator_path} exceeds the limit by {exceeded_by} byte(s).",
            constraint,
            **kwargs,
        )
        self.violator_path = violator_path
        self.exceeded_by = exceeded_by


class SizeConstraintSubceededError(SizeConstraintViolatedError):
    def __init__(self, constraint, **kwargs):
        super().__init__(
            f"Violated size constraint: {constraint.constraint_path} = {constraint.size_max} bytes should be parsed by now, but {constraint.size_already} bytes were actually parsed",
            constraint,
            **kwargs,
        )


class AnticipatedSizeConstraintExceededError(SizeConstraintViolatedError):
    def __init__(
        self, constraint, violator_path, violator_value, exceeded_by, **kwargs
    ):
        super().__init__(
            f"Anticipating violation of size constraint {constraint.constraint_path} = {constraint.size_max}: already parsed {constraint.size_already} bytes and {violator_path} = {violator_value} indicates that the limit will be exceeded by >= {exceeded_by} byte(s).",
            constraint,
            **kwargs,
        )
        self.violator_path = violator_path
        self.violator_value = violator_value
        self.exceeded_by = exceeded_by
