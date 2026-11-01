#!/usr/bin/env bash
# Regression for the LXC 203/EXEC caused by umask 077 creating bin/ as 0700.
set -Eeuo pipefail

receiver=deploy/install-staging.sh
bootstrap=deploy/bootstrap-lxc.sh

# Fail CI if a future refactor silently reintroduces mkdir -p under umask 077.
grep -Fq 'install -d -m 0755 -o root -g root "$base/releases" "$base/bin"' "$receiver"
grep -Fq '/opt/donnarieix-auth /opt/donnarieix-auth/releases /opt/donnarieix-auth/bin' "$bootstrap"
grep -Fq 'runuser -u donnarieix-auth -- test -x "$live"' "$receiver"

# Reproduce the mode creation on an isolated directory, with root owning the
# executable and a separate unprivileged system account needing traversal.
tmp="$(mktemp -d)"
trap 'sudo rm -rf -- "$tmp"' EXIT
chmod 0755 "$tmp"
sudo env BASE="$tmp" bash -c '
    set -Eeuo pipefail
    umask 077
    mkdir -p "$BASE/bin"
    [[ "$(stat -c %a "$BASE/bin")" == 700 ]]
    install -d -m 0755 -o root -g root "$BASE/bin"
    install -m 0755 -o root -g root /bin/true "$BASE/bin/auth"
    [[ "$(stat -c %a "$BASE/bin")" == 755 ]]
    runuser -u nobody -- test -x "$BASE/bin/auth"
'
echo "Executable directory permission regression test passed"
