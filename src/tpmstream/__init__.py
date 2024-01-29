__version__ = "0.1.10"

# make tcti_init visible for py-tcti
# see https://github.com/tpm2-software/tpm2-tss/pull/2749
from tpmstream.tcti import tcti_init  # isort:skip
