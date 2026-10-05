#!/usr/bin/env bash
# Experiment 5: the verifier must fail CLEARLY on each attack / mistake.
#
# NOTE on fixture construction: `ssh-keygen -Y sign -f <privkey>` signs with the
# BARE KEY even when a matching -cert.pub exists. To produce a signature that
# embeds a certificate you must go through an ssh-agent holding key+cert and
# point -f at the certificate. Getting this wrong makes rogue-CA tests pass for
# the wrong reason.
set -uo pipefail
LAB="${BEAMSIG_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export BEAMSIG_HOME="$LAB"
B="$LAB/bin/beamsig"
CA="$LAB/ca/pinned-user-ca.txt"
T="$LAB/exp5"
rm -rf "$T"; mkdir -p "$T"
cd "$T"

pass=0; fail=0
check() { # check <expect: ok|reject> <label> <cmd...>
  local expect="$1" label="$2"; shift 2
  local out rc
  out=$("$@" 2>&1); rc=$?
  echo "-------------------------------------------------------------------"
  echo "TEST   : $label"
  echo "EXPECT : $expect   RC: $rc"
  echo "$out" | sed 's/^/       | /' | head -6
  if { [ "$expect" = ok ] && [ "$rc" -eq 0 ]; } || \
     { [ "$expect" = reject ] && [ "$rc" -ne 0 ]; }; then
    echo "RESULT : PASS"; pass=$((pass+1))
  else
    echo "RESULT : *** UNEXPECTED ***"; fail=$((fail+1))
  fi
}

NS=beamsig.artifact.v1

# ---- genuine beam fixtures ---------------------------------------------
printf 'genuine beam artifact\n' > good.txt
SSH_AUTH_SOCK="$LAB/run/agent.sock" "$B" sign good.txt -n "$NS" -o good.sig
SSH_AUTH_SOCK="$LAB/run/agent.sock" "$B" sign good.txt -n some.other.namespace -o otherns.sig
NOW=$(date -u +%s)
printf 'genuine beam artifacT\n' > tampered.txt

# ---- rogue CA fixtures, signed THROUGH AN AGENT so the cert is embedded --
ssh-keygen -q -t ecdsa -b 256 -f rogueca   -N '' -C rogue-ca
ssh-keygen -q -t ecdsa -b 256 -f rogueuser -N '' -C rogue-user

mkcert() { # mkcert <outprefix> <keyid> <extension-args...>
  local out="$1" keyid="$2"; shift 2
  cp rogueuser "$out"; cp rogueuser.pub "$out.pub"
  ssh-keygen -q -s rogueca -I "$keyid" -n root,beams -V -5m:+60m "$@" "$out.pub"
}

# (a) forged bot-name, matching a real beam id
mkcert forged beam-forged \
  -O extension:bot-name@goteleport.com=beam-1786bcd6-04b9-4b9e-ad87-0c13071df7e9 \
  -O extension:bot-instance-id@goteleport.com=deadbeef-0000-0000-0000-000000000000
# (b) a cert with NO bot-name at all (an ordinary human user cert)
mkcert human 'alice@example.com'
# (c) a Machine ID bot that is NOT a beam
mkcert otherbot bot-ci -O extension:bot-name@goteleport.com=ci-runner

# start a throwaway agent and sign with each CERT
eval "$(ssh-agent -s)" >/dev/null
for n in forged human otherbot; do
  ssh-add -q "$n" 2>/dev/null
  ssh-keygen -Y sign -q -f "$n-cert.pub" -n "$NS" good.txt 2>/dev/null
  mv good.txt.sig "$n.sig"
  ssh-add -q -D 2>/dev/null
done
ssh-agent -k >/dev/null 2>&1 || true
unset SSH_AUTH_SOCK SSH_AGENT_PID

# sanity: confirm the fixtures really embed certificates
echo "### fixture sanity check (must all say 'is certificate : True') ###"
for n in good forged human otherbot; do
  printf '%-10s ' "$n.sig"; "$B" inspect -s "$n.sig" | grep 'is certificate'
done

# allowed_signers trusting the rogue CA (for the ssh-keygen contrast)
echo "* cert-authority $(cut -d' ' -f1,2 rogueca.pub)" > rogue_allowed_signers
# a beamsig CA pin file trusting the ROGUE CA, to isolate non-CA checks
cut -d' ' -f1,2 rogueca.pub > rogue_ca_pin.txt

echo
echo "###################################################################"
echo "# POSITIVE CONTROL"
echo "###################################################################"
check ok "genuine beam signature, correct payload, time now" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$CA" --claimed-time "$NOW"
check ok "genuine beam signature, --beam-id matches" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$CA" --claimed-time "$NOW" --beam-id "$BEAM_ID"

echo
echo "###################################################################"
echo "# NEGATIVE TESTS"
echo "###################################################################"
check reject "TAMPERED PAYLOAD" \
  "$B" verify tampered.txt -s good.sig -n "$NS" --ca "$CA" --claimed-time "$NOW"

# Discovery is on by default, so pinning the wrong CA does NOT block
# verification: the correct user CA is fetched for the cluster the certificate
# names. --ca is a seed, not a whitelist. The knobs that actually restrict are
# --offline, --cluster and --discover-allow, so test those instead.
check ok     "WRONG CA pinned, discovery on -> still verifies (--ca is not a whitelist)" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$LAB/ca/export-host.txt" --claimed-time "$NOW"

check reject "WRONG CA pinned, --offline -> trust anchors gate" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$LAB/ca/export-host.txt" \
       --offline --claimed-time "$NOW"

check reject "discovery on, but --cluster names a different tenant" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$LAB/ca/export-host.txt" \
       --cluster other.example.sh --claimed-time "$NOW"

check reject "discovery on, but --discover-allow excludes this cluster" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$LAB/ca/export-host.txt" \
       --discover-allow '*.nope.example' --claimed-time "$NOW"

check reject "ROGUE CA + FORGED bot-name, checked against the REAL Teleport CA" \
  "$B" verify good.txt -s forged.sig -n "$NS" --ca "$CA" --claimed-time "$NOW"

check reject "CERT WITHOUT bot-name (ordinary user cert), its own CA trusted" \
  "$B" verify good.txt -s human.sig -n "$NS" --ca rogue_ca_pin.txt --claimed-time "$NOW"

check reject "BOT THAT IS NOT A BEAM (bot-name=ci-runner), its own CA trusted" \
  "$B" verify good.txt -s otherbot.sig -n "$NS" --ca rogue_ca_pin.txt --claimed-time "$NOW"

check reject "TIMESTAMP AFTER the cert window (+1 year)" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$CA" --claimed-time "$((NOW + 31536000))"

check reject "TIMESTAMP BEFORE the cert window (-1 year)" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$CA" --claimed-time "$((NOW - 31536000))"

check reject "TIMESTAMP 2h after signing (cert lifetime is only 61m)" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$CA" --claimed-time "$((NOW + 7200))"

check reject "NAMESPACE CONFUSION (signature made for another namespace)" \
  "$B" verify good.txt -s otherns.sig -n "$NS" --ca "$CA" --claimed-time "$NOW"

check reject "WRONG --beam-id demanded" \
  "$B" verify good.txt -s good.sig -n "$NS" --ca "$CA" --claimed-time "$NOW" \
       --beam-id 00000000-0000-0000-0000-000000000000

echo
echo "###################################################################"
echo "# CONTRAST: plain ssh-keygen -Y verify on the FORGED cert"
echo "# (rogue CA trusted, as it would be if an attacker controlled the pin,"
echo "#  or if a verifier trusted any CA in a bundle)"
echo "###################################################################"
ssh-keygen -Y verify -f rogue_allowed_signers -I root -n "$NS" -s forged.sig < good.txt 2>&1
echo "rc=$?"
echo
echo "The forged cert carries bot-name@goteleport.com=beam-1786bcd6-...  "
echo "ssh-keygen reports only the principal 'root'. It never reads, checks or"
echo "prints the bot-name extension, so it cannot distinguish a beam from any"
echo "other certificate holder. That is why beamsig exists."
echo
echo "--- and what ssh-keygen -Y find-principals reports for the forged cert ---"
ssh-keygen -Y find-principals -s forged.sig -f rogue_allowed_signers 2>&1

echo
echo "==================================================================="
echo "PASS=$pass  UNEXPECTED=$fail"
[ "$fail" -eq 0 ]
