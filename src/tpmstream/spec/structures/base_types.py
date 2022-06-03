from ..common.base_type import _INT


class UINT8(_INT):
    _int_size = 1


class BYTE(_INT):
    _int_size = 1


class INT8(_INT):
    _int_size = 1


class BOOL(_INT):
    _int_size = 1


class UINT16(_INT):
    _int_size = 2


class INT16(_INT):
    _int_size = 2


class UINT32(_INT):
    _int_size = 4


class INT32(_INT):
    _int_size = 4


class UINT64(_INT):
    _int_size = 8


class INT64(_INT):
    _int_size = 8


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
