from ..common.base_type import _INT, _UINT
from ..common.values import ValidValues


class UINT8(_UINT):
    _int_size = 1
    _valid_values = ValidValues(range(0, 2**8))


class BYTE(UINT8):
    pass


class INT8(_INT):
    _int_size = 1
    _valid_values = ValidValues(range(-(2**7), 2**7))


class BOOL(UINT8):
    _valid_values = ValidValues(range(0, 2))


class UINT16(_UINT):
    _int_size = 2
    _valid_values = ValidValues(range(0, 2**16))


class INT16(_INT):
    _int_size = 2
    _valid_values = ValidValues(range(-(2**15), 2**15))


class UINT32(_UINT):
    _int_size = 4
    _valid_values = ValidValues(range(0, 2**32))


class INT32(_INT):
    _int_size = 4
    _valid_values = ValidValues(range(-(2**31), 2**31))


class UINT64(_UINT):
    _int_size = 8
    _valid_values = ValidValues(range(0, 2**64))


class INT64(_INT):
    _int_size = 8
    _valid_values = ValidValues(range(-(2**63), 2**63))


class TPM_ALGORITHM_ID(UINT32):
    pass


class TPM_MODIFIER_INDICATOR(UINT32):
    pass


class TPM_AUTHORIZATION_SIZE(UINT32):
    pass


class TPM_PARAMETER_SIZE(UINT32):
    pass


class TPM_KEY_SIZE(UINT16):
    pass


class TPM_KEY_BITS(UINT16):
    pass
