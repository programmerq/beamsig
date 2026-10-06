#!/usr/bin/env bash
# Turn on beam-attributable git signing for the whole beam, via ~/.gitconfig.
#
#   bin/install-global.sh              install
#   bin/install-global.sh --uninstall  remove every key we set
#   bin/install-global.sh --no-autosign    install, but don't sign by default
#   bin/install-global.sh --no-showsig     install, but don't show sigs in git log
#
# After this, `git commit` in ANY repository in this beam is signed by the beam,
# and `git log` shows who signed it. No ssh-agent and no SSH_AUTH_SOCK are
# needed: bin/git-beamsig-keygen talks to Teleport's hardware key agent directly
# and re-reads the certificate on every signature, so the ~20 minute
# certificate rotation is invisible.
set -euo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CFG="${BEAMSIG_CONFIG_DIR:-$HOME/.config/beamsig}"

KEYS=(
  user.name user.email
  gpg.format gpg.ssh.program gpg.ssh.allowedSignersFile user.signingkey
  commit.gpgsign tag.gpgsign log.showSignature
)

if [ "${1:-}" = "--uninstall" ]; then
  for k in "${KEYS[@]}"; do
    git config --global --unset-all "$k" 2>/dev/null || true
  done
  echo "Removed beamsig keys from ~/.gitconfig:"
  printf '  %s\n' "${KEYS[@]}"
  echo "Left $CFG in place; delete it by hand if you want it gone."
  exit 0
fi

AUTOSIGN=true; SHOWSIG=true; EXTRA_CLUSTERS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --no-autosign) AUTOSIGN=false ;;
    --no-showsig)  SHOWSIG=false ;;
    --trust)       shift; EXTRA_CLUSTERS+=("${1:?--trust needs a cluster}") ;;
    --trust=*)     EXTRA_CLUSTERS+=("${1#--trust=}") ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

: "${BEAM_ID:?BEAM_ID is not set; are you inside a beam?}"
: "${TELEPORT_CLUSTER:?TELEPORT_CLUSTER is not set}"

if [ ! -x "$LAB/venv/bin/python" ]; then
  echo "run $LAB/bin/setup.sh first" >&2
  exit 1
fi

mkdir -p "$CFG"
chmod 700 "$CFG"

echo "== pinning Teleport SSH user CAs =="
# Pin by value, not by URL: a verifier that re-fetches its own trust anchor is
# trusting the network, not the pin.
#
# The store is a directory of <cluster>.ca files. The filename is the cluster
# label, and verification takes the authoritative cluster from the pin rather
# than from the certificate -- which matters as soon as more than one tenant is
# trusted, because the certificate's cluster extension is only a claim made by
# whoever signed it. Nothing here is specific to this tenant: --trust <cluster>
# adds another, or drop a <cluster>.ca file in by hand.
STORE="$CFG/trusted"
mkdir -p "$STORE"
chmod 700 "$STORE"

pin_cluster() { # pin_cluster <cluster>
  local c="$1"
  curl -fsS "https://${c}/webapi/auth/export?type=user" -o "$STORE/${c}.ca" || {
    echo "   warning: could not fetch the user CA for $c" >&2
    rm -f "$STORE/${c}.ca"
    return 1
  }
  printf '   %s\n' "$STORE/${c}.ca"
}

pin_cluster "$TELEPORT_CLUSTER"
cp "$STORE/${TELEPORT_CLUSTER}.ca" "$CFG/pinned-user-ca.txt"
CLUSTERS=("$TELEPORT_CLUSTER")
for c in ${EXTRA_CLUSTERS[@]+"${EXTRA_CLUSTERS[@]}"}; do
  if [ "$c" != "$TELEPORT_CLUSTER" ] && pin_cluster "$c"; then
    CLUSTERS+=("$c")
  fi
done

# allowed_signers is what stock ssh-keygen consults, and it has no notion of
# which cluster a CA belongs to; list every trusted cluster's CA.
#
# Build it from the store rather than from the clusters we just pinned, so that
# anything already discovered survives. Writing only the pinned set clobbered
# previously discovered CAs, which left cross-tenant commits stuck at %G?=U.
BEAMSIG_HOME="$LAB" "$LAB/venv/bin/python" -c '
import sys, os
sys.path.insert(0, os.environ["BEAMSIG_HOME"])
from beamsig import allowedsigners
n = allowedsigners.sync()
print(f"   {allowedsigners.default_path()}  ({n} CAs, pins + discovered)")
' || "$LAB/bin/make-allowed-signers.sh" 'beams' "${CLUSTERS[@]}" > "$CFG/allowed_signers"
CA_FP=$("$LAB/venv/bin/python" - "$CFG/pinned-user-ca.txt" <<'PY'
import sys, base64, hashlib
for tok in open(sys.argv[1]).read().split():
    if tok.startswith("AAAA"):
        print("SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(tok)).digest()).decode().rstrip("="))
        break
PY
)
echo "   $CFG/pinned-user-ca.txt  ($CA_FP)"

# A current copy of the certificate. The shim ignores user.signingkey and
# refreshes this file itself on every signature, so it never goes stale; it is
# here so that manual `ssh-keygen -Y sign` and other tools have something real.
"$LAB/bin/split-identity.sh" \
  "${TELEPORT_IDENTITY_FILE:-/var/run/tbot/identity/identity}" "$CFG/split" >/dev/null
cp "$CFG/split/ssh-cert.pub" "$CFG/beam-cert.pub"
echo "   $CFG/beam-cert.pub"

# the uuid -> alias mapping that exists nowhere in any certificate
printf '%s %s\n' "$BEAM_ID" "${BEAM_ALIAS:-unknown}" > "$CFG/alias-map"
echo "   $CFG/alias-map  (self-reported; the alias is in no credential)"

echo "== writing ~/.gitconfig =="
git config --global user.name  "beam-$BEAM_ID"
git config --global user.email "$(
  "$LAB/venv/bin/python" -c "
import sys; sys.path.insert(0,'$LAB')
from beamsig import identity, sshcert
print(sshcert.parse_line(identity.load().ssh_cert_line).key_id)")"
git config --global gpg.format ssh
git config --global gpg.ssh.program "$LAB/bin/git-beamsig-keygen"
git config --global gpg.ssh.allowedSignersFile "$CFG/allowed_signers"
git config --global user.signingkey "$CFG/beam-cert.pub"
git config --global commit.gpgsign "$AUTOSIGN"
git config --global tag.gpgsign "$AUTOSIGN"
git config --global log.showSignature "$SHOWSIG"

for k in "${KEYS[@]}"; do
  printf '  %-28s %s\n' "$k" "$(git config --global --get "$k")"
done

cat <<EOF

Done. Every repository in this beam now signs as beam-$BEAM_ID.

  git commit -m msg          signed automatically ($AUTOSIGN)
  git log                    shows the beam signer ($SHOWSIG)
  git log --format='%G?|%GS' G|beam-$BEAM_ID

Caveats worth knowing:
  * log.showSignature=true runs a verification per commit shown, which spawns a
    python process each time. Fine for a demo, slow on a long history. Use
    'git log --no-show-signature', or install with --no-showsig.
  * This signs in EVERY repo, including ones you push to GitHub, which cannot
    verify Teleport certificates and will label the commits "Unverified".
  * The signer shown is the beam. The certificate Key ID is the owner
    ($(git config --global --get user.email)), who is impersonated, not the signer.
  * Trust is per tenant: ${CLUSTERS[*]}.
    Add another with: $0 --trust <cluster>
    or: $LAB/bin/beamsig trust <cluster>
  * Undo with: $0 --uninstall
EOF
