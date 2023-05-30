import io

# TEST_PATH = os.path.abspath(__file__)
# PCAP_DIRECORY_PATH = os.path.join(os.path.dirname(TEST_PATH), "pcap/*.pcap")
#
#
# def get_comand_code(binary_blob) -> TPM_CC:
#     return TPM_CC(int.from_bytes(binary_blob[6:10], byteorder="big"))
#
#
# def get_test_name(path, command_code):
#     file_basename = os.path.basename(path).split(".")[0]
#     # remove leading "TPM_CC_"
#     command_code = str(command_code)[len(TPM_CC.__name__) + 1 :]
#     return f"{file_basename}_{command_code}"
#
#
# # TODO rm
# def tpm_binary_blob_generator(pcap_direcory_path):
#     paths = sorted(glob.glob(pcap_direcory_path))
#
#     for path in paths:
#         with open(path, "rb") as file:
#             pcapng = dpkt.pcapng.Reader(file)
#             for ts, buf in pcapng:
#                 # command or response
#                 binary_blob = dpkt.ip.IP(buf).data.data
#                 yield path, binary_blob
#
#
# def tpm_command_generator(pcap_direcory_path=PCAP_DIRECORY_PATH, names=False):
#     binary_blob_gen = tpm_binary_blob_generator(pcap_direcory_path=pcap_direcory_path)
#     if names:
#         yield from (
#             get_test_name(path, get_comand_code(binary_blob))
#             for path, binary_blob in itertools.islice(binary_blob_gen, 0, None, 2)
#         )
#         return
#
#     yield from (
#         binary_blob
#         for path, binary_blob in itertools.islice(binary_blob_gen, 0, None, 2)
#     )
#
#
# def tpm_response_generator(pcap_direcory_path=PCAP_DIRECORY_PATH, names=False):
#     binary_blob_gen = tpm_binary_blob_generator(pcap_direcory_path=pcap_direcory_path)
#
#     command_code = None
#     for path, binary_blob in binary_blob_gen:
#         if command_code is None:
#             # command
#             command_code = get_comand_code(binary_blob)
#         else:
#             # response
#             if names:
#                 yield get_test_name(path, command_code)
#             else:
#                 yield binary_blob, command_code
#             command_code = None


def bytes_from_files(files):
    """Iterator. If path is None or empty, read from stdin."""
    if isinstance(files, io.BufferedReader):
        files = (files,)

    for file in files:
        # workaround https://bugs.python.org/issue14156
        if file.mode == "r":
            file = file.buffer

        while True:
            buffer = file.read()
            if not buffer:
                break
            yield from (byte for byte in buffer)
