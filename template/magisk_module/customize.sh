SKIPUNZIP=1

MODULE_ID=@MODULE_ID@

TMP_MODULE_DIR=/data/local/tmp/libsec

if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86" ] && [ "$ARCH" != "x64" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print    "*********************************************************"
  ui_print    "! Unable to extract verify.sh!"
  ui_print    "! This zip may be corrupted, please try downloading again"
  abort "*********************************************************"
fi
. $TMPDIR/verify.sh

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh' "$MODPATH"

mkdir -p "$MODPATH/webroot"
extract "$ZIPFILE" 'webroot/index.html' "$MODPATH/webroot" true
extract "$ZIPFILE" 'webroot/main.js' "$MODPATH/webroot" true

LIB32_NAME="armeabi-v7a.so"
LIB64_NAME="arm64-v8a.so"
LIB32_DEST="$MODPATH/zygisk"
LIB64_DEST="$MODPATH/zygisk"
BUSYBOX_BIN=/data/adb/magisk/busybox

if [ ! -f $BUSYBOX_BIN ]; then
  BUSYBOX_BIN=/data/adb/ksu/bin/busybox
fi

if [ ! -f $BUSYBOX_BIN ]; then
  BUSYBOX_BIN=/data/adb/ap/bin/busybox
fi

if [ ! -f $BUSYBOX_BIN ]; then
  abort "! unable to locate busybox"
fi

ui_print "- Using busybox: $BUSYBOX_BIN"

[ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ] && LIB32_NAME="x86.so"
[ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ] && LIB64_NAME="x86_64.so"

mkdir -p "$LIB32_DEST"
mkdir -p "$LIB64_DEST"

ui_print "- Extracting 32-bit libraries"
extract "$ZIPFILE" "lib/$LIB32_NAME" "$LIB32_DEST" true

if [ "$IS64BIT" = true ]; then
  ui_print "- Extracting 64-bit libraries"
  extract "$ZIPFILE" "lib/$LIB64_NAME" "$LIB64_DEST" true
fi

ui_print "- Extracting bundled frida gadget"

mkdir -p "$TMP_MODULE_DIR"
extract "$ZIPFILE" "gadget/libgadget-$ARCH.so.xz" "$TMP_MODULE_DIR" true
mv "$TMP_MODULE_DIR/libgadget-$ARCH.so.xz" "$TMP_MODULE_DIR/libsecmon.so.xz"
$BUSYBOX_BIN unxz "$TMP_MODULE_DIR/libsecmon.so.xz"

if [ "$IS64BIT" = true ]; then
  ARCH32="arm"
  [ "$ARCH" = "x64" ] && ARCH32="x86"

  extract "$ZIPFILE" "gadget/libgadget-$ARCH32.so.xz" "$TMP_MODULE_DIR" true
  mv "$TMP_MODULE_DIR/libgadget-$ARCH32.so.xz" "$TMP_MODULE_DIR/libsecmon32.so.xz"
  $BUSYBOX_BIN unxz "$TMP_MODULE_DIR/libsecmon32.so.xz"
fi

extract "$ZIPFILE" "config.json.example" "$TMP_MODULE_DIR" true

ui_print "- Writing default gadget config (listen mode)"
echo '{"interaction":{"type":"listen","address":"0.0.0.0","port":27042}}' > "$TMP_MODULE_DIR/libsecmon.config.so"

set_perm_recursive "$TMP_MODULE_DIR" 0 0 0755 0644
set_perm_recursive "$MODPATH" 0 0 0755 0644
