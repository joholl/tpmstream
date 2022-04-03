def is_list(type) -> bool:
    # not typed
    if type is list:
        return True
    # typed list
    if hasattr(type, "__origin__") and type.__origin__ is list:
        return True
    return False
