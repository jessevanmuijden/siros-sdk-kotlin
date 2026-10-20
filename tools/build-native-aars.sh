#!/usr/bin/env bash
# Builds the zk-cred-vega and zk-cred-longfellow AARs from checkouts of their nymauth PR branches into a plain Maven
# directory, so the SDK / sample app can use them without publishing anything (docs/NATIVE_DEV.md).
#
#   tools/build-native-aars.sh --vega <checkout> --longfellow <checkout> [--out <dir>] [--vendor] [--abis "arm64-v8a ..."]
#
# Each checkout must be AT the pinned full commit (checked, not assumed). --vendor also regenerates the UniFFI Kotlin
# bindings from the built libraries into sdk/credentials/src/main/kotlin/uniffi/ (they must come from the same build as the
# AAR: they check the library's API checksums when it loads). Requires cargo, cargo-ndk, the Android NDK
# (ANDROID_NDK_HOME) and the Android targets of rustup. Output: <out>/org/siros/<artifact>/<version>/.
set -euo pipefail

VEGA_SHA=d6f0955bf60379e4e81c242e13b5ecbd8e28a271          # sirosfoundation/zk-cred-vega PR #13 (feat/nymauth-prove)
LONGFELLOW_SHA=cf2eba996ba1fac247539d515d8bab502da48f94    # sirosfoundation/zk-cred-longfellow PR #13 (feat/nymauth-prove)
VEGA_VERSION=0.0.7                                         # the crate says 0.0.6, which is already released (v0.0.6, no nymauth): built under the next version so it cannot be mistaken for it
LONGFELLOW_VERSION=0.1.2                                    # the crate says 0.1.1: built under the next version so it cannot be mistaken for the released one

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/build/native-repo"; vega=""; lf=""; vendor=0
while [ $# -gt 0 ]; do
  case "$1" in
    --vega) vega="$2"; shift 2;;
    --longfellow) lf="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    --vendor) vendor=1; shift;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done
[ -n "$vega$lf" ] || { echo "give --vega and/or --longfellow" >&2; exit 2; }

check_sha() { # dir expected
  local have; have="$(git -C "$1" rev-parse HEAD)"
  [ "$have" = "$2" ] || { echo "$1 is at $have, expected $2 (check the PR head before building; it may have moved)" >&2; exit 1; }
  [ -z "$(git -C "$1" status --porcelain --untracked-files=no)" ] || { echo "$1 has local changes" >&2; exit 1; }
}

build() { # dir artifact version crate sha
  local dir="$1" artifact="$2" version="$3" crate="$4"
  ( cd "$dir" && make aar pom VERSION="$version" )
  local dest="$out/org/siros/$artifact/$version"
  mkdir -p "$dest"
  cp "$dir/target/${crate//-/_}-$version.aar" "$dest/$artifact-$version.aar"
  cp "$dir/target/$artifact-$version.pom" "$dest/$artifact-$version.pom"
  echo "built $dest"
}

vendor_bindings() { # dir crate (generated from the Android arm64 library of the same build)
  local dir="$1" crate="$2" lib="$1/target/aarch64-linux-android/release/lib$2.so"
  ( cd "$dir" && cargo run --release --features uniffi --bin uniffi-bindgen -- generate --library "$lib" --language kotlin --out-dir "$dir/target/kotlin-bindings" )
  mkdir -p "$here/sdk/credentials/src/main/kotlin/uniffi/$crate"
  cp "$dir/target/kotlin-bindings/uniffi/$crate/$crate.kt" "$here/sdk/credentials/src/main/kotlin/uniffi/$crate/$crate.kt"
  if [ "$crate" = zk_cred_vega ]; then
    # The generated NymAuthVegaException variants have a field named `message`, which clashes with Throwable.message and does
    # not compile. Renamed to `detail` in the Kotlin only (UniFFI reads fields by position); the proper fix is a different
    # field name in zk-cred-vega's NymAuthVegaError.
    python3 - "$here/sdk/credentials/src/main/kotlin/uniffi/zk_cred_vega/zk_cred_vega.kt" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
a = s.index("sealed class NymAuthVegaException")
b = s.index("companion object ErrorHandler", a) if "companion object ErrorHandler" in s[a:] else a + 6000
seg = s[a:b].replace("val `message`: kotlin.String", "val `detail`: kotlin.String").replace('get() = "message=${ `message` }"', 'get() = "message=${ `detail` }"')
s = s[:a] + seg + s[b:]
c = s.index("object FfiConverterTypeNymAuthVegaError") if "object FfiConverterTypeNymAuthVegaError" in s else a
s = s[:c] + s[c:].replace("value.`message`", "value.`detail`", 40)
open(p, "w").write(s)
PY
  fi
  echo "vendored bindings for $crate"
}

if [ -n "$vega" ]; then check_sha "$vega" "$VEGA_SHA"; build "$vega" zk-cred-vega "$VEGA_VERSION" zk-cred-vega; [ $vendor = 1 ] && vendor_bindings "$vega" zk_cred_vega; fi
if [ -n "$lf" ]; then check_sha "$lf" "$LONGFELLOW_SHA"; build "$lf" zk-cred-longfellow "$LONGFELLOW_VERSION" zk-cred-longfellow; [ $vendor = 1 ] && vendor_bindings "$lf" zk_cred_longfellow; fi
echo "Use: ./gradlew -PsirosNativeRepo=$out ..."
