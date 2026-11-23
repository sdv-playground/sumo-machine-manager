#!/usr/bin/env bash
#
# Neutral-names guard — sumo is a generic open-source stack; the names of the
# downstream products, devices and organisations that consume it stay out of
# its tree. Fails if DENY matches any tracked file outside this script and the
# allow-list.
#
#     bash scripts/check-neutral-names.sh
#
# scripts/neutral-names.allow lists the FUNCTIONAL identifiers that still carry
# such a name (a path the code opens, a binary it execs — renaming them changes
# behaviour), one `path:literal  # reason` per line. A hit is allowed when
# removing every literal listed for its path leaves no match; an entry that no
# longer matches anything fails the run, so the list only shrinks.
set -euo pipefail

cd "$(dirname "$0")/.."

DENY='supernova|\bcvc\b|mmgr-cvc|cvc-mmgr|traton|lynxion|scania'
ALLOW=scripts/neutral-names.allow

allow_path=()
allow_lit=()
allow_used=()
while IFS= read -r entry; do
    entry=${entry%% # *}
    entry=${entry%"${entry##*[![:space:]]}"}
    [[ -z $entry || $entry == \#* ]] && continue
    allow_path+=("${entry%%:*}")
    allow_lit+=("${entry#*:}")
    allow_used+=(0)
done <"$ALLOW"

fail=0
while IFS= read -r hit; do
    path=${hit%%:*}
    rest=${hit#*:}
    text=${rest#*:}
    for i in "${!allow_path[@]}"; do
        if [[ ${allow_path[$i]} == "$path" && $text == *"${allow_lit[$i]}"* ]]; then
            text=${text//"${allow_lit[$i]}"/}
            allow_used[i]=1
        fi
    done
    if printf '%s\n' "$text" | grep -qiE "$DENY"; then
        echo "neutral-names: $hit"
        fail=1
    fi
done < <(git grep -inIE "$DENY" -- . ':!scripts/check-neutral-names.sh' ":!$ALLOW" || true)

for i in "${!allow_path[@]}"; do
    if [[ ${allow_used[$i]} == 0 ]]; then
        echo "neutral-names: stale allow entry ${allow_path[$i]}:${allow_lit[$i]}"
        fail=1
    fi
done

if [[ $fail == 1 ]]; then
    echo "neutral-names: FAILED — use a neutral name, or list a functional identifier in $ALLOW"
    exit 1
fi
echo "neutral-names: ok"
