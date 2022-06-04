import io


def bytes_from_files(files):
    """Iterator. If path is None or empty, read from stdin."""
    if isinstance(files, io.BufferedReader):
        files = (files,)

    for file in files:
        while True:
            buffer = file.read()
            if not buffer:
                break
            yield from (byte for byte in buffer)
