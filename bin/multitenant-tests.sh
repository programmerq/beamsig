#!/usr/bin/env bash
# Multi-tenant trust tests.
#
# beamsig must not be wired to one Teleport tenant, and trusting two tenants
# must not let either impersonate the other. A certificate's
# teleport-route-to-cluster extension is only a claim made by whoever signed
# it, so the authoritative cluster has to come from the pin.
#
# A second tenant is simulated with a local CA, since we only have one real
# cluster. That is sufficient: the question is whether trust is keyed by CA.
set -uo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
B="$LAB/bin/beamsig"
T="$LAB/exp-multitenant"
REAL_CLUSTER="${TELEPORT_CLUSTER:?set TELEPORT_CLUSTER}"
FAKE_CLUSTER="other-tenant.example.sh"
NS=beamsig.artifact.v1

rm -rf "$T"; mkdir -p "$T/store"; cd "$T"

pass=0; fail=0
check() { local expect="$1" label="$2"; shift 2
  local out rc; out=$("$@" 2>&1); rc=$?
  echo "-------------------------------------------------------------------"
  echo "TEST   : $label"
  echo "EXPECT : $expect   RC: $rc"
  echo "$out" | sed 's/^/       | /' | head -7
  if { [ "$expect" = ok ] && [ "$rc" -eq 0 ]; } ||
     { [ "$expect" = reject ] && [ "$rc" -ne 0 ]; }; then
    echo "RESULT : PASS"; pass=$((pass+1))
  else echo "RESULT : *** UNEXPECTED ***"; fail=$((fail+1)); fi
}

printf 'genuine artifact\n' > good.txt

# --- tenant 1: the real beam -------------------------------------------
"$B" sign good.txt -n "$NS" -o real.sig >/dev/null
cp "$HOME/.config/beamsig/trusted/${REAL_CLUSTER}.ca" "store/${REAL_CLUSTER}.ca"

# --- tenant 2: a simulated cluster, with its own CA ---------------------
ssh-keygen -q -t ecdsa -b 256 -f otherca -N '' -C "other-tenant-ca"
ssh-keygen -q -t ecdsa -b 256 -f otheruser -N '' -C "other-tenant-beam"
OTHER_BEAM=5d41402a-bc4b-2a76-b971-9d911017c592

# a beam of tenant 2, honestly labelled
cp otheruser otherbeam; cp otheruser.pub otherbeam.pub
ssh-keygen -q -s otherca -I 'alice@example.sh' -n root,beams -V -5m:+60m \
  -O extension:bot-name@goteleport.com="beam-$OTHER_BEAM" \
  -O "extension:bot-instance-id@goteleport.com=aaaaaaaa-0000-0000-0000-000000000000" \
  -O "extension:teleport-route-to-cluster=$FAKE_CLUSTER" \
  otherbeam.pub

# the attack: tenant 2's CA mints a cert CLAIMING to belong to tenant 1
cp otheruser spoof; cp otheruser.pub spoof.pub
ssh-keygen -q -s otherca -I 'owner@example.com' -n root,beams -V -5m:+60m \
  -O extension:bot-name@goteleport.com="beam-$OTHER_BEAM" \
  -O "extension:teleport-route-to-cluster=$REAL_CLUSTER" \
  spoof.pub

eval "$(ssh-agent -s)" >/dev/null
for n in otherbeam spoof; do
  ssh-add -q "$n" 2>/dev/null
  ssh-keygen -Y sign -q -f "$n-cert.pub" -n "$NS" good.txt 2>/dev/null
  mv good.txt.sig "$n.sig"
  ssh-add -q -D 2>/dev/null
done
ssh-agent -k >/dev/null 2>&1 || true
unset SSH_AUTH_SOCK SSH_AGENT_PID

# pin tenant 2 under its correct cluster label
cut -d' ' -f1,2 otherca.pub > "store/${FAKE_CLUSTER}.ca"

echo "### trust store now holds two tenants ###"
"$B" trust --list --store store
echo

echo "###################################################################"
echo "# both tenants verify from one store, neither hardwired"
echo "###################################################################"
check ok "tenant 1 (real beam) verifies" \
  "$B" verify good.txt -s real.sig -n "$NS" --ca store --claimed-time "$(date -u +%s)"
check ok "tenant 2 (simulated beam) verifies from the SAME store" \
  "$B" verify good.txt -s otherbeam.sig -n "$NS" --ca store --claimed-time "$(date -u +%s)"

echo
echo "###################################################################"
echo "# --cluster scopes a verification to one tenant"
echo "###################################################################"
check ok "tenant 2 signature, --cluster $FAKE_CLUSTER" \
  "$B" verify good.txt -s otherbeam.sig -n "$NS" --ca store \
       --cluster "$FAKE_CLUSTER" --claimed-time "$(date -u +%s)"
check reject "tenant 2 signature, --cluster $REAL_CLUSTER demanded" \
  "$B" verify good.txt -s otherbeam.sig -n "$NS" --ca store \
       --cluster "$REAL_CLUSTER" --claimed-time "$(date -u +%s)"

echo
echo "###################################################################"
echo "# CROSS-TENANT SPOOFING: tenant 2 mints a cert claiming tenant 1"
echo "###################################################################"
echo "The spoof certificate's own extension says:"
"$B" inspect -s spoof.sig | sed -n 's/^  teleport-route-to-cluster/  claims cluster:/p'
echo
check reject "spoof is NOT accepted as tenant 1 (--cluster $REAL_CLUSTER)" \
  "$B" verify good.txt -s spoof.sig -n "$NS" --ca store \
       --cluster "$REAL_CLUSTER" --claimed-time "$(date -u +%s)"
echo "And when verified without --cluster, it is attributed to the tenant whose"
echo "CA actually signed it, with the false claim flagged:"
"$B" verify good.txt -s spoof.sig -n "$NS" --ca store --claimed-time "$(date -u +%s)" \
  2>&1 | grep -E "teleport cluster|cluster claimed|^  !" | sed 's/^/       | /'

echo
echo "###################################################################"
echo "# an unlabelled pin cannot vouch for a cluster name"
echo "###################################################################"
mkdir -p unlabelled && cp "store/${REAL_CLUSTER}.ca" unlabelled/ca-no-cluster-label
# strip the clustername= annotation too, so nothing identifies the tenant
cut -d' ' -f1,2,3 "store/${REAL_CLUSTER}.ca" > unlabelled/ca-no-cluster-label
"$B" verify good.txt -s real.sig -n "$NS" --ca unlabelled/ca-no-cluster-label \
  --claimed-time "$(date -u +%s)" 2>&1 \
  | grep -E "result|teleport cluster|^  !" | sed 's/^/       | /'

echo
echo "==================================================================="
echo "PASS=$pass UNEXPECTED=$fail"
[ "$fail" -eq 0 ]
