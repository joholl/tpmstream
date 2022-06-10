from tpmstream.common.event import MarshalEvent
from tpmstream.io.pretty.unmarshal import get_type_name

try:
    from colorama import init
    from colorama.ansi import Fore, Style
except ModuleNotFoundError:
    # mock for brython
    class Fore:
        def __getattr__(self, _name):
            return ""

    class Style:
        def __getattr__(self, _name):
            return ""

else:
    init()


def unmarshal(events: list[MarshalEvent]):
    """Generator. Take iterable which yields MarshalEvent. Yield strings."""
    for event in iter(events):
        type_name = f"{Fore.BLUE}{get_type_name(event.type)}{Style.RESET_ALL}"
        name = f"{Fore.LIGHTGREEN_EX}{event.path}{Style.RESET_ALL}"
        value = f"{Fore.YELLOW} = {'...' if event.value is ... else event.value}{Style.RESET_ALL}"
        yield f"{type_name.ljust(50)}{name}{value}"
