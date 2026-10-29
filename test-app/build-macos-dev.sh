#!/bin/bash
# Build and sign macOS app for WebAuthn platform authenticator development
#
# PREREQUISITES:
# 1. Run ./setup-dev.sh to generate src-tauri/Entitlements.plist
# 2. Register App ID (identifier from src-tauri/tauri.conf.json) with Associated Domains
#    at https://developer.apple.com/account/resources/identifiers/list
# 3. Create a Mac Development provisioning profile at:
#    https://developer.apple.com/account/resources/profiles/list
# 4. Place the downloaded profile as: test-app/embedded.provisionprofile
# 5. Deploy apple-app-site-association on the associated domain (see Entitlements.plist)
#
# Run this script from anywhere; it operates on its own directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration - derived from config files
ENTITLEMENTS="src-tauri/Entitlements.plist"
PROVISIONING_PROFILE="embedded.provisionprofile"
TAURI_CONF="src-tauri/tauri.conf.json"

# ---------------------------------------------------------------------------
# Prerequisite checks
#
# These must run BEFORE any value extraction: reading a missing plist makes
# PlistBuddy exit 1, which would abort the script with a cryptic
# "Entry ... Does Not Exist" instead of the guidance below.
# ---------------------------------------------------------------------------

if [ ! -f "$ENTITLEMENTS" ]; then
    echo "ERROR: Entitlements file not found at $ENTITLEMENTS"
    echo ""
    echo "Generate it with your Team ID, bundle ID and associated domain:"
    echo "   cd $SCRIPT_DIR && ./setup-dev.sh"
    exit 1
fi

if [ ! -f "$TAURI_CONF" ]; then
    echo "ERROR: Tauri config not found at $TAURI_CONF"
    exit 1
fi

if [ ! -f "$PROVISIONING_PROFILE" ]; then
    echo "ERROR: Provisioning profile not found at $PROVISIONING_PROFILE"
    echo ""
    echo "You need to create a Mac Development provisioning profile:"
    echo ""
    echo "1. Go to https://developer.apple.com/account/resources/identifiers/list"
    echo "   - Register the App ID from $TAURI_CONF"
    echo "   - Enable: Associated Domains"
    echo ""
    echo "2. Go to https://developer.apple.com/account/resources/profiles/list"
    echo "   - Click '+' to create a new profile"
    echo "   - Select 'macOS App Development'"
    echo "   - Select your App ID"
    echo "   - Select your development certificate"
    echo "   - Select your Mac device(s)"
    echo "   - Download the profile"
    echo ""
    echo "3. Copy the downloaded .provisionprofile file to:"
    echo "   $SCRIPT_DIR/$PROVISIONING_PROFILE"
    echo ""
    exit 1
fi

# ---------------------------------------------------------------------------
# Pull values from their source-of-truth config files
#
# jq -r prints the string "null" (and exits 0) for a missing key, so use -e to
# fail loudly rather than building a path like ".../null.app".
# ---------------------------------------------------------------------------

BUNDLE_ID=$(jq -er '.identifier' "$TAURI_CONF")
APP_NAME=$(jq -er '.productName' "$TAURI_CONF")
TEAM_ID=$(/usr/libexec/PlistBuddy -c "Print :com.apple.developer.team-identifier" "$ENTITLEMENTS")

if [ -z "$TEAM_ID" ]; then
    echo "ERROR: com.apple.developer.team-identifier is empty in $ENTITLEMENTS"
    exit 1
fi

# ---------------------------------------------------------------------------
# Validate the provisioning profile against the entitlements
#
# A stale or mismatched profile still signs cleanly but makes passkey requests
# fail at runtime with an opaque error, so catch it here instead.
#
# `security cms -D` exits 0 even on undecodable input, so test the output.
# ---------------------------------------------------------------------------

PROFILE_PLIST="$(mktemp -t webauthn-profile)"
trap 'rm -f "$PROFILE_PLIST"' EXIT

security cms -D -i "$PROVISIONING_PROFILE" >"$PROFILE_PLIST" 2>/dev/null || true
if [ ! -s "$PROFILE_PLIST" ]; then
    echo "ERROR: Could not decode $PROVISIONING_PROFILE"
    echo "The file may be corrupt or not a provisioning profile."
    exit 1
fi

# macOS profiles carry com.apple.application-identifier; iOS profiles use the
# unprefixed application-identifier. Accept either so this keeps working if the
# profile is generated for a different platform target.
PROFILE_APP_ID=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.application-identifier" "$PROFILE_PLIST" 2>/dev/null || echo "")
if [ -z "$PROFILE_APP_ID" ]; then
    PROFILE_APP_ID=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" "$PROFILE_PLIST" 2>/dev/null || echo "")
fi
if [ -z "$PROFILE_APP_ID" ]; then
    echo "ERROR: Could not read an application identifier from $PROVISIONING_PROFILE"
    exit 1
fi
EXPECTED_APP_ID="$TEAM_ID.$BUNDLE_ID"

# Profiles may carry a wildcard App ID (TEAMID.com.example.*), which is valid
# for any matching bundle ID.
case "$PROFILE_APP_ID" in
    "$EXPECTED_APP_ID") ;;
    *\*)
        if [[ "$EXPECTED_APP_ID" != ${PROFILE_APP_ID%\*}* ]]; then
            echo "ERROR: Provisioning profile does not cover this app."
            echo "  Profile App ID:  $PROFILE_APP_ID"
            echo "  This app:        $EXPECTED_APP_ID"
            exit 1
        fi
        ;;
    *)
        echo "ERROR: Provisioning profile does not match this app."
        echo "  Profile App ID:  $PROFILE_APP_ID"
        echo "  Expected:        $EXPECTED_APP_ID"
        echo ""
        echo "Re-download a profile for App ID $BUNDLE_ID, or re-run ./setup-dev.sh"
        echo "if the Team ID or bundle identifier changed."
        exit 1
        ;;
esac

# Expiry check is best-effort: PlistBuddy date formatting is locale dependent,
# so a parse failure skips the check rather than blocking the build.
PROFILE_EXPIRY=$(/usr/libexec/PlistBuddy -c "Print :ExpirationDate" "$PROFILE_PLIST" 2>/dev/null || echo "")
if [ -n "$PROFILE_EXPIRY" ]; then
    EXPIRY_EPOCH=$(date -j -f "%a %b %d %T %Z %Y" "$PROFILE_EXPIRY" +%s 2>/dev/null || echo "")
    if [ -n "$EXPIRY_EPOCH" ] && [ "$EXPIRY_EPOCH" -lt "$(date +%s)" ]; then
        echo "ERROR: Provisioning profile expired on $PROFILE_EXPIRY"
        echo "Download a fresh profile from"
        echo "  https://developer.apple.com/account/resources/profiles/list"
        exit 1
    fi
fi

# The profile must list this Mac. Apple silicon Macs are matched by their
# Provisioning UDID, which is NOT the Hardware UUID -- registering the latter
# yields a profile that signs cleanly but is refused at launch with
# "Launchd job spawn failed" (POSIX error 163).
PROFILE_DEVICES=$(/usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" "$PROFILE_PLIST" 2>/dev/null || echo "")
if [ -n "$PROFILE_DEVICES" ]; then
    HW_INFO=$(system_profiler SPHardwareDataType 2>/dev/null || echo "")
    THIS_UDID=$(printf '%s' "$HW_INFO" | sed -n 's/.*Provisioning UDID: *//p' | head -1)
    THIS_HW_UUID=$(printf '%s' "$HW_INFO" | sed -n 's/.*Hardware UUID: *//p' | head -1)

    if [ -n "$THIS_UDID" ] && ! printf '%s' "$PROFILE_DEVICES" | grep -qF "$THIS_UDID"; then
        echo "ERROR: this Mac is not in the provisioning profile's device list."
        echo "  Provisioning UDID: $THIS_UDID"
        if [ -n "$THIS_HW_UUID" ] && printf '%s' "$PROFILE_DEVICES" | grep -qF "$THIS_HW_UUID"; then
            echo ""
            echo "The profile lists this Mac's Hardware UUID instead:"
            echo "  $THIS_HW_UUID"
            echo "That identifier works for Intel Macs. Apple silicon is matched on"
            echo "the Provisioning UDID, so the entry does not authorize this machine."
        fi
        echo ""
        echo "Register the device at"
        echo "  https://developer.apple.com/account/resources/devices/list"
        echo "with Platform: macOS and Device ID: $THIS_UDID"
        echo "Then edit and save the profile so it picks the device up, and"
        echo "download it again."
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Find a signing identity belonging to $TEAM_ID
#
# The parenthetical in an "Apple Development: ..." common name is the
# certificate's own ID, not the team, e.g.
#   CN=Apple Development: dev@example.com (P55387UKSL), OU=86TDY6D9V2
# The team is the OU, so read that rather than trusting `head -1`. Signing with
# another team's certificate either fails late or produces a bundle whose
# webcredentials association silently does not work.
# ---------------------------------------------------------------------------

IDENTITY=""
IDENTITY_HASH=""
MATCH_COUNT=0
ALL_CANDIDATES=""

# Each line is "<sha1> <common name>" so the chosen identity can later be
# matched against the certificates the profile authorizes.
while IFS= read -r line; do
    [ -n "$line" ] || continue
    cand_hash="${line%% *}"
    candidate="${line#* }"
    ALL_CANDIDATES="$ALL_CANDIDATES  $candidate"$'\n'
    cert_team=$(security find-certificate -c "$candidate" -p 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null \
        | tr ',/' '\n\n' \
        | sed -n 's/^ *OU *= *//p' \
        | head -1)
    if [ "$cert_team" = "$TEAM_ID" ]; then
        MATCH_COUNT=$((MATCH_COUNT + 1))
        if [ -z "$IDENTITY" ]; then
            IDENTITY="$candidate"
            IDENTITY_HASH="$cand_hash"
        fi
    fi
done <<<"$(security find-identity -v -p codesigning \
    | sed -n 's/^ *[0-9][0-9]*) \([0-9A-Fa-f]*\) "\(Apple Development[^"]*\)".*/\1 \2/p')"

if [ -z "$IDENTITY" ]; then
    echo "ERROR: No valid Apple Development signing identity found for team $TEAM_ID."

    # `find-identity -v` lists only usable identities, so an expired certificate
    # is indistinguishable from having none at all. Re-query without -v to
    # report the actual reason.
    UNUSABLE=$(security find-identity -p codesigning 2>/dev/null \
        | grep "Apple Development" \
        | grep "CSSMERR" || true)

    if [ -n "$UNUSABLE" ]; then
        echo ""
        echo "Found certificates that cannot be used:"
        printf '%s\n' "$UNUSABLE" | sed 's/^ */  /'
        echo ""
        echo "CSSMERR_TP_CERT_EXPIRED means the certificate needs renewing:"
        echo "  Xcode > Settings > Accounts > select your Apple ID"
        echo "    > Manage Certificates > '+' > Apple Development"
        echo ""
        echo "After issuing a new certificate, regenerate and re-download the"
        echo "provisioning profile. Development profiles embed the list of"
        echo "certificates permitted to sign, so $PROVISIONING_PROFILE will not"
        echo "include the replacement."
    elif [ -n "$ALL_CANDIDATES" ]; then
        echo ""
        echo "Available Apple Development identities (none in team $TEAM_ID):"
        printf '%s' "$ALL_CANDIDATES"
        echo ""
        echo "Either install a certificate for team $TEAM_ID, or re-run"
        echo "./setup-dev.sh with the Team ID these certificates belong to."
    else
        echo "Make sure you have a valid development certificate installed."
    fi
    exit 1
fi

if [ "$MATCH_COUNT" -gt 1 ]; then
    echo "NOTE: $MATCH_COUNT identities match team $TEAM_ID; using the first."
fi

# ---------------------------------------------------------------------------
# The profile must authorize the certificate we are about to sign with
#
# Development profiles embed the certificates permitted to sign. codesign
# succeeds regardless of this, so a mismatch only surfaces later as a refused
# launch, with no indication that the profile is at fault.
# ---------------------------------------------------------------------------

PROFILE_HAS_IDENTITY=no
cert_index=0
while plutil -extract "DeveloperCertificates.$cert_index" raw -o - "$PROFILE_PLIST" >/dev/null 2>&1; do
    cert_fp=$(plutil -extract "DeveloperCertificates.$cert_index" raw -o - "$PROFILE_PLIST" 2>/dev/null \
        | base64 -d 2>/dev/null \
        | openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null \
        | sed 's/.*=//; s/://g' \
        | tr '[:lower:]' '[:upper:]')
    if [ "$cert_fp" = "$IDENTITY_HASH" ]; then
        PROFILE_HAS_IDENTITY=yes
        break
    fi
    cert_index=$((cert_index + 1))
done

if [ "$PROFILE_HAS_IDENTITY" != yes ]; then
    echo "ERROR: $PROVISIONING_PROFILE does not authorize the signing certificate."
    echo "  Identity: $IDENTITY"
    echo "  SHA-1:    $IDENTITY_HASH"
    echo ""
    echo "codesign would still succeed, but the app would be refused at launch"
    echo "with \"Launchd job spawn failed\" (POSIX error 163)."
    echo ""
    echo "In the developer portal open the profile, click Edit, tick this"
    echo "certificate, then Save. Downloading without editing first returns the"
    echo "same bytes and will not fix this."
    exit 1
fi

# Resolve the target directory rather than assuming src-tauri/target, which is
# wrong under CARGO_TARGET_DIR or a custom --target.
TARGET_DIR=$(cd src-tauri && cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.target_directory')
if [ -z "$TARGET_DIR" ] || [ "$TARGET_DIR" = "null" ]; then
    TARGET_DIR="$SCRIPT_DIR/src-tauri/target"
fi

# ---------------------------------------------------------------------------
# Use Xcode's Swift toolchain
#
# swift-rs compiles macos/ (swift-tools-version 6.1) during the cargo build. A
# swiftly-managed `swift` earlier on PATH is often older and fails with
# "package 'macos' is using Swift tools version 6.1.0 but the installed
# version is ...". scripts/test-macos.sh does the same thing.
# ---------------------------------------------------------------------------

# Only `swift` is redirected, via a directory holding a single symlink. Putting
# the whole toolchain bin on PATH would also shadow /usr/bin/cc, and the
# toolchain's cc has no default SDK, which breaks C crates that compile vendored
# sources with "'sys/types.h' file not found".
XCODE_SWIFT="$(xcrun --find swift 2>/dev/null || true)"
if [ -z "$XCODE_SWIFT" ]; then
    echo "ERROR: could not locate Xcode's swift via xcrun."
    echo "Install Xcode, then select it with:"
    echo "  sudo xcode-select -s /Applications/Xcode.app"
    exit 1
fi
SWIFT_SHIM_DIR="$(mktemp -d -t webauthn-swift-shim)"
trap 'rm -f "$PROFILE_PLIST"; rm -rf "$SWIFT_SHIM_DIR"' EXIT
ln -sf "$XCODE_SWIFT" "$SWIFT_SHIM_DIR/swift"
PATH="$SWIFT_SHIM_DIR:$PATH"
export PATH

SWIFT_VERSION=$(swift --version 2>/dev/null | sed -n 's/.*Apple Swift version \([0-9.][0-9.]*\).*/\1/p' | head -1)

# A non-system `cc` (devenv/nix) cannot find the macOS System library. Only
# override the linker in that case, and never clobber an explicit RUSTFLAGS.
if [ "$(command -v cc)" != "/usr/bin/cc" ] && [ -z "${RUSTFLAGS:-}" ]; then
    echo "NOTE: non-system cc found ($(command -v cc)); linking with /usr/bin/cc"
    RUSTFLAGS="-C linker=/usr/bin/cc"
    export RUSTFLAGS
fi

echo "=== Building macOS App for WebAuthn Development ==="
echo "Swift: ${SWIFT_VERSION:-unknown} ($(command -v swift))"
echo "Team ID: $TEAM_ID"
echo "Bundle ID: $BUNDLE_ID"
echo "Signing Identity: $IDENTITY"
echo "Profile App ID: $PROFILE_APP_ID"
echo ""

# Step 1: Build the Tauri app as a bundle (debug mode)
echo "Step 1: Building Tauri app bundle..."
pnpm tauri build --debug --bundles app

BUNDLE_PATH="$TARGET_DIR/debug/bundle/macos/${APP_NAME}.app"

if [ ! -d "$BUNDLE_PATH" ]; then
    echo "ERROR: Bundle not found at $BUNDLE_PATH"
    echo "Make sure 'pnpm tauri build --debug --bundles app' succeeded."
    exit 1
fi

echo "Bundle found at: $BUNDLE_PATH"

# Step 2: Copy provisioning profile into bundle.
# This must happen before signing: the profile is covered by the code seal.
echo ""
echo "Step 2: Embedding provisioning profile..."
cp "$PROVISIONING_PROFILE" "$BUNDLE_PATH/Contents/embedded.provisionprofile"

# Step 3: Sign the bundle with entitlements.
# --force replaces any signature the Tauri bundler applied, so there is no need
# to --remove-signature first. --timestamp is omitted deliberately: development
# builds are not notarized, and the timestamp server round-trip would make this
# fail offline.
echo ""
echo "Step 3: Signing bundle with entitlements..."
codesign --force \
    --sign "$IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    --timestamp=none \
    "$BUNDLE_PATH"

# Step 4: Verify the signature is actually valid.
# `codesign -dv` only displays a signature, so validate first and let a failure
# abort the script before "Build Complete" is printed.
echo ""
echo "Step 4: Verifying signature..."
codesign --verify --strict --verbose=2 "$BUNDLE_PATH"

echo ""
echo "Step 5: Signature details..."
# `head` closes the pipe after 20 lines; codesign then dies with SIGPIPE, which
# under `set -o pipefail` would abort this script before it reaches the launch
# step below. This is a display-only step, so swallow that pipe failure.
codesign -dv --verbose=4 "$BUNDLE_PATH" 2>&1 | head -20 || true

echo ""
echo "Step 6: Verifying entitlements..."
codesign -d --entitlements - "$BUNDLE_PATH" 2>&1

echo ""
echo "=== Build Complete ==="
echo ""
echo "The signed app bundle is at:"
echo "  $BUNDLE_PATH"
echo ""
echo "To run: open '$BUNDLE_PATH'"
echo ""
echo "Or run directly: '$BUNDLE_PATH/Contents/MacOS/$APP_NAME'"
echo ""

# Launch the freshly built bundle. Set NO_OPEN=1 to build/sign without opening.
if [ "${NO_OPEN:-0}" != "1" ]; then
    echo "Opening $BUNDLE_PATH ..."
    open "$BUNDLE_PATH"
fi
