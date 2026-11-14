#!/usr/bin/env sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root="$here/../app/src/main/cpp"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
${CXX:-c++} -std=c++17 -Wall -Wextra -Werror -pedantic -I"$root" "$root/admin_routes.cpp" "$here/admin_routes_test.cpp" -o "$work/admin_routes_test"
"$work/admin_routes_test"
