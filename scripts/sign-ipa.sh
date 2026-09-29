#!/bin/bash
set -euo pipefail

INPUT_IPA="${1:?usage: sign-ipa.sh input.ipa [output.ipa]}"
OUTPUT_IPA="${2:-signed.ipa}"
: "${IOS_P12_BASE64:?Missing IOS_P12_BASE64 secret}"
: "${IOS_P12_PASSWORD:?Missing IOS_P12_PASSWORD secret}"
: "${IOS_MOBILEPROVISION_BASE64:?Missing IOS_MOBILEPROVISION_BASE64 secret}"
command -v zsign >/dev/null 2>&1 || {
  echo 'zsign is required to sign LCSign-modified IPA files' >&2
  exit 1
}

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

printf '%s' "$IOS_P12_BASE64" | base64 --decode > "$WORK/cert.p12"
printf '%s' "$IOS_MOBILEPROVISION_BASE64" | base64 --decode > "$WORK/profile.mobileprovision"

# Reject mismatched material before invoking the signer. Neither the private key
# nor its password is printed, persisted, or added to the repository.
if ! /usr/bin/openssl pkcs12 -in "$WORK/cert.p12" -passin env:IOS_P12_PASSWORD -noout >/dev/null 2>&1; then
  echo 'P12 validation failed: the uploaded file and P12 password do not match' >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_IPA")"

# Read the root bundle identifier with Apple's plist parser before zsign opens
# the binary plist. zsign's internal UTF-16 reader does not combine surrogate
# pairs, so non-BMP characters such as emoji can become a different identifier
# inside the Mach-O CodeDirectory even though Info.plist still looks correct.
BUNDLE_PLIST_ENTRY="$(LC_ALL=C unzip -Z1 "$INPUT_IPA" | LC_ALL=C awk -F/ '$1 == "Payload" && $2 ~ /\.app$/ && $3 == "Info.plist" { print; exit }')"
[ -n "$BUNDLE_PLIST_ENTRY" ] || {
  echo 'Unable to locate the root app Info.plist in the IPA' >&2
  exit 1
}
unzip -p "$INPUT_IPA" "$BUNDLE_PLIST_ENTRY" > "$WORK/input-Info.plist"
BUNDLE_ID="$(plutil -extract CFBundleIdentifier raw -o - "$WORK/input-Info.plist")"
[ -n "$BUNDLE_ID" ] || {
  echo 'Unable to read CFBundleIdentifier from the root app Info.plist' >&2
  exit 1
}

# zsign follows the same nested-code model as LCSign: injected dylibs and
# frameworks are signed as code objects without inheriting the root app's
# entitlements, while app/extension bundles receive the provisioning profile.
# LCSign's working output contains SHA-1 and SHA-256 CodeDirectories. Current
# zsign defaults to SHA-256 only, so explicitly request its dual-hash mode.
#
# Enable iOS Files integration. zsign intentionally rewrites Info.plist while
# applying this setting; both binary and XML plist formats are valid to iOS.
# Passing -b is still avoided for ordinary bundle IDs because it is unnecessary.
# Non-ASCII IDs need -b because zsign otherwise mishandles UTF-16 surrogate
# pairs (notably emoji) while building the CodeDirectory.
ZSIGN_ARGS=(
  -f
  --legacy_sha1
  -z 9
  -S
  -k "$WORK/cert.p12"
  -p "$IOS_P12_PASSWORD"
  -m "$WORK/profile.mobileprovision"
  -o "$OUTPUT_IPA"
)

if LC_ALL=C printf '%s' "$BUNDLE_ID" | LC_ALL=C grep -q '[^[:print:]]'; then
  echo 'Using explicit bundle ID for non-ASCII Bundle ID compatibility'
  ZSIGN_ARGS+=( -b "$BUNDLE_ID" )
else
  echo 'Enabled Files app access (document browser and file sharing)'
fi

zsign "${ZSIGN_ARGS[@]}" "$INPUT_IPA"

[ -s "$OUTPUT_IPA" ] || {
  echo 'zsign did not create a signed IPA' >&2
  exit 1
}

# Confirm that the archive contains exactly one root app before uploading it.
APP_COUNT="$(LC_ALL=C unzip -Z1 "$OUTPUT_IPA" | LC_ALL=C sed -n 's#^Payload/\([^/]*\.app\)/.*#\1#p' | LC_ALL=C sort -u | wc -l | tr -d ' ')"
[ "$APP_COUNT" = '1' ] || {
  echo "Signed IPA contains $APP_COUNT root app bundles; expected exactly one" >&2
  exit 1
}

echo "Created $OUTPUT_IPA with LCSign-compatible nested signing"
