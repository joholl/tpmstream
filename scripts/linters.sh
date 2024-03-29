#!/bin/sh
set -ex

DIR=$(pwd)
FILES="$(find -name "*.py" -not -path "./venv/*")"
CHECK=YES
LINTERS="autoflafke|black|isort"

usage () {
    echo "Usage: $0 [-c|--check] [-l|--linters=autoflafke,black,isort] [-h|--help] [PATH]"
}

while [ $# -gt 0 ]; do
    key="$1"

    case $key in
    -c|--check)
        CHECK=true
        shift
        ;;
    -l|--linters)
        LINTERS="$2"
        shift
        shift
        ;;
    -l=*|--linters=*)
        LINTERS="$1"
        shift
        ;;
    -h|--help)
        usage
        exit 0
        shift
        ;;
    -*)
        echo Unknown parameter "$1"
        usage
        exit 1
        ;;
    *)
        # does not check if multiple positionals were given
        DIR="$1"
        shift
        ;;
    esac
done

check_black=""
check_isort=""
if [ "${CHECK}" = true ]; then
    check_autoflake="--check"
    check_black="--diff --check"
    check_isort="--diff --check-only"
fi

case "${LINTERS}" in
    *"autoflafke"*)
    python -m autoflake --in-place --remove-all-unused-imports ${check_autoflake} ${FILES}
    ;;
esac

case "${LINTERS}" in
    *"black"*)
    python -m black ${check_black} "${DIR}"
    ;;
esac

case "${LINTERS}" in
    *"isort"*)
    python -m isort ${check_isort} "${DIR}"
    ;;
esac
