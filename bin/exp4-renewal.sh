#!/usr/bin/env bash
# Experiment 4 (cont): do signed commits survive certificate renewal and
# certificate EXPIRY?
#
# Timeline: tbot renews every 20 min; certs live 61 min. So a commit signed
# with generation N stays "recent" for 61 minutes and is then signed by an
# expired certificate. The question that matters for durability is whether
# `git verify-commit` still accepts it, i.e. whether git pins verify-time to
# the commit's committer date rather than to "now".
set -uo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
export SSH_AUTH_SOCK="$LAB/run/agent.sock"
R="$LAB/repos/renewal"
LOG="$LAB/logs/exp4-renewal.txt"
exec > >(tee -a "$LOG") 2>&1

cur_window() {
  "$LAB/venv/bin/python" -c "
import sys; sys.path.insert(0,'$LAB')
from beamsig import identity, sshcert
c=sshcert.parse_line(identity.load().ssh_cert_line)
print(c.valid_after, c.valid_before)"
}

commit_now() { # commit_now <label>
  local label="$1"
  echo "$label $(date -u +%s)" >> "$R/log.txt"
  git -C "$R" add log.txt
  if ! git -C "$R" commit -q -m "$label"; then
    echo "[$(date -u +%H:%M:%SZ)] COMMIT FAILED for '$label'"
    return 1
  fi
  local h; h=$(git -C "$R" rev-parse --short HEAD)
  read -r va vb < <(cur_window)
  echo "[$(date -u +%H:%M:%SZ)] committed $h  '$label'  cert window $(date -u -d @"$va" +%H:%M:%SZ)..$(date -u -d @"$vb" +%H:%M:%SZ)"
  echo "$h $va $vb $label" >> "$R/.manifest"
}

if [ "${1:-}" = "init" ]; then
  rm -rf "$R"; mkdir -p "$R"; git init -q "$R"
  git -C "$R" config user.name "beam-$BEAM_ID"
  git -C "$R" config user.email "owner@example.com"
  git -C "$R" config gpg.format ssh
  git -C "$R" config user.signingkey "$LAB/exp2/beam-cert.pub"
  git -C "$R" config gpg.ssh.allowedSignersFile "$LAB/exp2/allowed_signers"
  git -C "$R" config commit.gpgsign true
  : > "$R/.manifest"
  echo "=== experiment 4 renewal test, started $(date -u) ==="
  commit_now "gen-A (first cert generation)"
  exit 0
fi

if [ "${1:-}" = "commit" ]; then
  # refresh the signing cert file from the (renewed) identity file
  "$LAB/bin/split-identity.sh" /var/run/tbot/identity/identity "$LAB/inventory/split" >/dev/null
  cp "$LAB/inventory/split/ssh-cert.pub" "$LAB/exp2/beam-cert.pub"
  commit_now "${2:-gen-next}"
  exit 0
fi

if [ "${1:-}" = "verify" ]; then
  echo
  echo "=== verification pass at $(date -u +%H:%M:%SZ) ==="
  while read -r h va vb label; do
    now=$(date -u +%s)
    state="VALID"; [ "$now" -ge "$vb" ] && state="EXPIRED $(( (now-vb)/60 ))m ago"
    echo "---------------------------------------------------------------"
    echo "commit $h  ($label)"
    echo "  signing cert: $(date -u -d @"$va" +%H:%M:%SZ)..$(date -u -d @"$vb" +%H:%M:%SZ)  [$state]"
    out=$(git -C "$R" verify-commit "$h" 2>&1); rc=$?
    echo "  git verify-commit  : rc=$rc  $(echo "$out" | head -1)"
    out2=$("$LAB/bin/beamsig" verify-commit "$h" -C "$R" \
            --ca "$LAB/ca/pinned-user-ca.txt" --beam-id "$BEAM_ID" 2>&1); rc2=$?
    echo "  beamsig verify-commit: rc=$rc2  $(echo "$out2" | grep -E 'result|FAILED' | head -1)"
  done < "$R/.manifest"
  exit 0
fi

echo "usage: $0 {init|commit [label]|verify}"
