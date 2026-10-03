#!/usr/bin/env bash
# Module: packaging.generate_package
# Purpose: Dispatch distribution package generation.
# Created: 2026-10-01
# Architecture: This entry point selects the package builder for the requested distribution.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)
output=${SLATE_PACKAGE_OUTPUT:-"$repo/../../outputs"}

usage() {
    printf 'Usage: %s [--output DIR] [--select "1,3"] [--build ubuntu_26.04] [--build debian_13] [--dry-run] [--list]\n' "$0"
}

selection=''
declare -a build_names=()
dry_run=0
list_only=0
while (($#)); do
    case "$1" in
        --output) (($# >= 2)) || { usage >&2; exit 2; }; output=$2; shift 2 ;;
        --select) (($# >= 2)) || { usage >&2; exit 2; }; selection=$2; shift 2 ;;
        --build) (($# >= 2)) || { usage >&2; exit 2; }; build_names+=("$2"); shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        --list) list_only=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

declare -a numbers names labels
while IFS='|' read -r number name label _; do
    [[ -n "$number" && "$number" != \#* ]] || continue
    numbers+=("$number")
    names+=("$name")
    labels+=("$label")
done < "$here/profiles.tsv"

if ((list_only)) || { [[ -z "$selection" ]] && ((${#build_names[@]} == 0)); }; then
    printf 'Slate NTFS packages (amd64):\n'
    for i in "${!numbers[@]}"; do
        case "${names[i]}" in
            ubuntu*) cli_name="ubuntu_${names[i]#ubuntu}" ;;
            linuxmint*) cli_name="linuxmint_${names[i]#linuxmint}" ;;
            debian*) cli_name="debian_${names[i]#debian}" ;;
        esac
        printf '  %s) %-38s --build %s\n' "${numbers[i]}" "${labels[i]}" "$cli_name"
    done
fi
if ((list_only)); then exit 0; fi

if ((${#build_names[@]})) && [[ -n "$selection" ]]; then
    echo 'Use either --build or --select, not both.' >&2
    exit 2
fi

if ((${#build_names[@]})); then
    for name in "${build_names[@]}"; do
        name=${name//_/}
        found=0
        for i in "${!names[@]}"; do
            if [[ "$name" == "${names[i]}" ]]; then
                selection+=" ${numbers[i]}"
                found=1
                break
            fi
        done
        ((found)) || { printf 'Unknown package name: %s\n' "$name" >&2; exit 2; }
    done
elif [[ -z "$selection" ]]; then
    if [[ ! -t 0 ]]; then
        echo 'Pass --select when standard input is not interactive.' >&2
        exit 2
    fi
    read -r -p 'Enter one or more numbers (spaces or commas): ' selection
fi

selection=${selection//,/ }
read -r -a requested <<< "$selection"
((${#requested[@]})) || { echo 'No package selected.' >&2; exit 2; }

declare -A seen
declare -a chosen
for number in "${requested[@]}"; do
    [[ "$number" =~ ^[1-9][0-9]*$ ]] || {
        printf 'Invalid selection: %s\n' "$number" >&2; exit 2;
    }
    found=0
    for i in "${!numbers[@]}"; do
        if [[ "$number" == "${numbers[i]}" ]]; then
            found=1
            if [[ ! -v seen[$number] ]]; then
                seen[$number]=1
                chosen+=("$i")
            fi
            break
        fi
    done
    ((found)) || { printf 'Unknown package number: %s\n' "$number" >&2; exit 2; }
done

for i in "${chosen[@]}"; do
    printf '\nGenerating %s...\n' "${labels[i]}"
    if ((dry_run)); then
        printf '  %s %s amd64\n' "${names[i]}" "$output"
    else
        mkdir -p "$output"
        "$here/deb/build-deb.sh" "${names[i]}" "$output" amd64
    fi
done
