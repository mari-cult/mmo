#!/usr/bin/env bash
set -euo pipefail

filtered=()
skip_next=0
for arg in "$@"; do
    if [ "$skip_next" -eq 1 ]; then
        skip_next=0
        continue
    fi
    case "$arg" in
        -fuse-ld=lld)
            continue
            ;;
        -flavor)
            skip_next=1
            continue
            ;;
    esac
    filtered+=("$arg")
done

exec lld-link "${filtered[@]}"
