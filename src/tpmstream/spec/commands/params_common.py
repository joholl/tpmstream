from functools import lru_cache

from tpmstream.spec.common.values import tpm_dataclass
from tpmstream.spec.structures.base_types import BYTE, UINT16


@tpm_dataclass
class TPM2B_ENCRYPTED_PARAM:
    size: UINT16
    encryptedParam: list[BYTE]


@tpm_dataclass
class TPMS_PARAMS:
    _encrypted = False

    @classmethod
    @lru_cache(maxsize=1)
    def encrypted(cls):
        """Returns a modified type where first parameter type is TPM2B_ENCRYPTED_PARAM. Result is cached to enable equality checks on it."""
        new_type = type(cls.__name__, (), {})

        assert hasattr(
            cls, "__annotations__"
        ), f"Parameter encryption failed: {cls.__name__} does not seem to have any parameters"
        params = cls.__annotations__
        assert list(params.values())[0].__name__.startswith(
            "TPM2B"
        ), f"Parameter encryption failed: expected TPM2B type for first param of {cls.__name__}, but found {list(params.values())[0].__name__} {list(params.keys())[0]}"
        first_param = {list(params.keys())[0]: TPM2B_ENCRYPTED_PARAM}
        other_params = dict(list(params.items())[1:])

        new_type.__annotations__ = {**first_param, **other_params}
        new_type._encrypted = True
        return tpm_dataclass(new_type)

    @staticmethod
    def is_encrypted_params(fields_dict: any) -> bool:
        """For encrypted params, the first field/param contains .size and .encryptedParam"""
        if not isinstance(fields_dict, dict):
            # fields_dict is obj (like TPMS_PARAMS(...))
            return hasattr(fields_dict, "_encrypted") and fields_dict._encrypted

        # fields_dict is dict of field_names, field_types (like fields of parameters)
        if len(fields_dict) == 0:
            return False
        first_field_value = list(fields_dict.values())[0]
        if not isinstance(first_field_value, dict):
            return False
        return list(first_field_value.keys()) == list(
            TPM2B_ENCRYPTED_PARAM.__annotations__.keys()
        )
