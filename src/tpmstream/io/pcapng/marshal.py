import io

import dpkt
from dpkt.dpkt import UnpackError

from ..binary import Binary


def tpm_pkgs_from_pcap_file(file):
    pcapng = dpkt.pcapng.Reader(file)

    for ts, pkg_bytes in pcapng:
        # try different parsers (eth packages went over 127.0.0.1, ip packages are from tpm2-tss tcti-pcap)
        for parser in (dpkt.ip.IP, dpkt.ethernet.Ethernet):
            try:
                pkg = parser(pkg_bytes)
                break
            except UnpackError:
                continue
        # call .data until result is bytes
        while not isinstance(pkg, bytes):
            pkg = pkg.data

        # skip if package is empty (or not long enough, like mssim platform commands)
        binary_blob = pkg
        if not binary_blob:
            continue
        if len(binary_blob) < 10:
            continue

        # for mssim, the response always has 4 extra bytes, remove
        size = int.from_bytes(binary_blob[2:6], byteorder="big")
        if size != len(binary_blob):
            binary_blob = binary_blob[:size]

        # TODO skip invalid packages?
        # valid_tags = (
        #     tag.to_bytes() for tag in TPMI_ST_COMMAND_TAG._valid_values._values
        # )
        # if not binary_blob.startswith(tuple(valid_tags)):
        #     continue

        # TODO if package is invalid (e.g. TPM2B size = 4000), it just doesnt stop parsing

        yield binary_blob


def bytes_from_pcap_file(file):
    for pkg_bytes in tpm_pkgs_from_pcap_file(file):
        yield from pkg_bytes


def marshal(tpm_type, buffer, root_path=None, command_code=None, **kwargs):
    """Generator. Take iterable which yields single bytes. Yield MarshalEvents."""
    # Emulate file from bytes
    # TODO bytes(buffer) consumes whole buffer... can we avoid this
    file = io.BytesIO(bytes(buffer))
    pkg_bytes = bytes_from_pcap_file(file)
    yield from Binary.marshal(
        tpm_type=tpm_type,
        buffer=pkg_bytes,
        root_path=root_path,
        command_code=command_code,
        **kwargs,
    )
