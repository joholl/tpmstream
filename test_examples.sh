#!/usr/bin/env bash

set -e
set -x


for c in $(python -m tpmstream ex); do echo " - $c" && python -m tpmstream ex $c; done
