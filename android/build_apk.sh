#!/usr/bin/env bash
# Build Is This A Scam? into a signed Android APK, with no Gradle.
#
# Chain: aapt2 (resources) -> javac -> d8 (dex) -> aapt2 link -> zipalign -> apksigner
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/../app"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
BT="$SDK/build-tools/34.0.0"
PLATFORM="$SDK/platforms/android-34/android.jar"
OUT="$ROOT/build"
KEYSTORE="$ROOT/isthisascam.keystore"
KEYPASS="isthisascam"

rm -rf "$OUT"
mkdir -p "$OUT"/{res,gen,classes,dex,assets/www}

echo "==> 1/7 compiling resources (aapt2 compile)"
"$BT/aapt2" compile --dir "$ROOT/app/src/main/res" -o "$OUT/res.zip"

echo "==> 2/7 linking resources (aapt2 link)"
"$BT/aapt2" link \
  -o "$OUT/base.apk" \
  -I "$PLATFORM" \
  --manifest "$ROOT/app/src/main/AndroidManifest.xml" \
  --java "$OUT/gen" \
  --min-sdk-version 24 \
  --target-sdk-version 34 \
  --version-code 1 --version-name 1.0.0 \
  "$OUT/res.zip"

echo "==> 3/7 compiling java (javac)"
javac -source 8 -target 8 -nowarn \
  -bootclasspath "$PLATFORM" \
  -classpath "$PLATFORM" \
  -d "$OUT/classes" \
  -encoding UTF-8 \
  $(find "$ROOT/app/src/main/java" "$OUT/gen" -name '*.java') 2>&1 | grep -viE "warning|bootstrap class path|deprecat" || true

echo "==> 4/7 dexing (d8)"
"$BT/d8" --min-api 24 --lib "$PLATFORM" \
  --output "$OUT/dex" \
  $(find "$OUT/classes" -name '*.class')

echo "==> 5/7 staging web assets"
cp "$APP/index.html" "$APP/ui.js" "$APP/core.js" "$OUT/assets/www/"

echo "==> 6/7 packaging (add dex + assets, zipalign)"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
(cd "$OUT/assets" && zip -q -r "$OUT/unsigned.apk" www)
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"

echo "==> 7/7 signing (apksigner)"
if [ ! -f "$KEYSTORE" ]; then
  keytool -genkeypair -v -keystore "$KEYSTORE" -alias isthisascam \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$KEYPASS" -keypass "$KEYPASS" \
    -dname "CN=Is This A Scam, O=IsThisAScam, C=FR" >/dev/null 2>&1
fi
"$BT/apksigner" sign \
  --ks "$KEYSTORE" --ks-key-alias isthisascam \
  --ks-pass "pass:$KEYPASS" --key-pass "pass:$KEYPASS" \
  --v1-signing-enabled true --v2-signing-enabled true \
  --out "$OUT/IsThisAScam.apk" "$OUT/aligned.apk"

"$BT/apksigner" verify --print-certs "$OUT/IsThisAScam.apk" | head -6
echo
echo "==> APK: $OUT/IsThisAScam.apk  ($(du -h "$OUT/IsThisAScam.apk" | cut -f1))"
"$BT/aapt2" dump badging "$OUT/IsThisAScam.apk" 2>/dev/null | head -6
