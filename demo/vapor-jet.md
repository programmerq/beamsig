# Signed from a second beam

This file was committed by beam `vapor-jet`
(`8bba9461-0638-4a00-9752-c9064f9d832f`) on the branch `vapor-jet-demo`.

That beam was provisioned by copying a single file, `setup-beamsig.sh`, onto a
fresh beam and running it. The script cloned this repository to `~/beamsig`,
built the virtualenv, generated the hardware key agent gRPC stubs, pinned the
cluster SSH user CA, wrote `~/.gitconfig`, and then proved the chain by signing
and verifying a throwaway commit.

## Why this file exists

To demonstrate **cross-beam verification**. This commit was signed by one beam
and is verified by a different one. The two share no secret. The only thing the
verifier needs is the cluster's SSH user CA, which is public:

    curl "https://$TELEPORT_CLUSTER/webapi/auth/export?type=user"

That works because the signature embeds the signer's whole Teleport
certificate, so `bot-name@goteleport.com` travels with the commit:

    beamsig verify-commit vapor-jet-demo --ca <pinned-ca> \
        --beam-id 8bba9461-0638-4a00-9752-c9064f9d832f

## What this does not prove

Read `../REPORT.md` section 4 before trusting any of it. Briefly:

- The certificate's Key ID is `jeff@goteleport.com`, the beam's **owner**, who
  is impersonated. It is not evidence the owner reviewed anything.
- Anything running inside the beam can sign as the beam; the signing agent
  requires no PIN, no touch and no client authentication.
- The beam's key never rotates, only its certificate does, so the signer
  chooses which validity window a verifier sees. The timestamp means
  "somewhere in this beam's lifetime", not a tight window.
- The alias `vapor-jet` is in no certificate and cannot be verified at all.
