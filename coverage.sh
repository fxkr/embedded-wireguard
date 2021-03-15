#!/bin/bash
set -x -euo pipefail
pio test -e native-test
cd "$( dirname "${BASH_SOURCE[0]}" )"
lcov -d .pio/build/native-test -c -o lcov.info --exclude "$(pwd)/test/tmp_pio_test_transport.cpp"
genhtml -o cov/ --demangle-cpp lcov.info
