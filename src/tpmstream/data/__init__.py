import sys
from importlib.resources import files

example_data_module = sys.modules[__name__]

# all files
example_data_files = files(example_data_module).iterdir()

# filter out all non-pcap files
example_data_files = list(filter(lambda f: f.suffix == ".pcap", example_data_files))
