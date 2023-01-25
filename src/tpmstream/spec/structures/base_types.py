from ..common.base_type import INT, UINT
from ..common.values import ValidValues


class UINT8(UINT):
    _int_size = 1
    _valid_values = ValidValues(range(0, 2**8))


class BYTE(UINT8):
    pass


class INT8(INT):
    _int_size = 1
    _valid_values = ValidValues(range(-(2**7), 2**7))


class BOOL(UINT8):
    _valid_values = ValidValues(range(0, 1))


class UINT16(UINT):
    _int_size = 2
    _valid_values = ValidValues(range(0, 2**16))


class INT16(INT):
    _int_size = 2
    _valid_values = ValidValues(range(-(2**15), 2**15))


class UINT32(UINT):
    _int_size = 4
    _valid_values = ValidValues(range(0, 2**32))


class INT32(INT):
    _int_size = 4
    _valid_values = ValidValues(range(-(2**31), 2**31))


class UINT64(UINT):
    _int_size = 8
    _valid_values = ValidValues(range(0, 2**64))


class INT64(INT):
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
