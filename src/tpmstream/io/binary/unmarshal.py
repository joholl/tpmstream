from tpmstream.common.event import InfoEvent, MarshalEvent


def unmarshal(events: list[MarshalEvent]):
    """Generator. Take iterable which yields MarshalEvent. Yield bytes (in chunks)."""
    yield from (to_bytes(event) for event in events)


def to_bytes(event: MarshalEvent) -> bytes:
    """Event to bytes. Zero-length bytes for ellipsis events."""
    if isinstance(event, InfoEvent):
        return b""

    if event.value is ...:
        return b""
    # is a primitive
    return event.value.to_bytes()
