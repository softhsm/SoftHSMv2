#! /bin/bash
# This file is in the public domain

set -x

if [[ "$ACTIONS_ORCHESTRATION_ID" == *"botan_x64"* ]] ; then
  echo "This test is not intended to be run with Botan, skipping." >&2
  exit 0
fi

export
CWD=`pwd`

# binaries

OPENSSL=${OPENSSL-openssl}
OPENSSL=`command -v "$OPENSSL"`
if test -z "$OPENSSL" ; then
  echo "error: openssl utility not found" >&2
  exit 77
fi

openssl() {
"$OPENSSL" ${1+"$@"}
}

openssl_version=`openssl version` || exit $?
if test -z "$openssl_version" ; then
  echo "cannot determine OpenSSL version" >&2
  exit 99
fi

case $openssl_version in
*"OpenSSL 0.9."*|\
*"OpenSSL 1."*|\
*"OpenSSL 3.0."*|\
*"OpenSSL 3.1."*|\
*"OpenSSL 3.2."*|\
*"OpenSSL 3.3."*|\
*"OpenSSL 3.4."*)
  echo "$openssl_version is not impacted" >&2
  exit 77
  ;;
esac
# NOTE OpenSSL > 3.5

if test "$RUNNER_OS" = "Windows" ; then
  D=`cd ../../../lib/Debug/ && pwd`
else
  D=`cd ../../../lib/.libs/ && pwd`
fi

if test -z "$D" ; then
  echo "unexpectedly missing library directory" >&2
  exit 99
fi

P11MODULE=
for S in so dll ; do
  for F in "$D"/*softhsm2.$S ; do
    test -f "$F" || continue
    P11MODULE="$F"
    break
  done
  test -n "$P11MODULE" && break
done
if test -z "$P11MODULE" ; then
  echo "error: unexpected module suffix" >&2
  exit 1
fi
if command -v realpath > /dev/null ; then
  P11MODULE=`realpath "$P11MODULE"`
fi

softhsm2_tool() {
    if test "$RUNNER_OS" = "Windows" ; then
        "$CWD"/../Debug/softhsm2-util.exe --module "$P11MODULE" ${1+"$@"}
    else
        "$CWD"/../softhsm2-util --module "$P11MODULE" ${1+"$@"}
    fi
}

clean_tokendir() {
rm -rf "$TOKEN_DIR"
}

# configurations
TOKEN_DIR="$CWD"/tokens
export SOFTHSM2_CONF="$TOKEN_DIR"/softhsm2.conf

clean_tokendir
mkdir -p "$TOKEN_DIR"

if test "$RUNNER_OS" = "Windows" ; then
  WINDOWS_TOKEN_DIR=`realpath "$TOKEN_DIR"`
  WINDOWS_TOKEN_DIR=`cygpath -w "$WINDOWS_TOKEN_DIR"`
  cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $WINDOWS_TOKEN_DIR
objectstore.backend = file
slots.removable = false
slots.mechanisms = ALL
log.level = DEBUG
log.file = $WINDOWS_TOKEN_DIR\token.log
EOF
else
  cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
slots.removable = false
slots.mechanisms = ALL
log.level = DEBUG
log.file = $TOKEN_DIR/token.log
EOF
fi

cat $SOFTHSM2_CONF

SOFTHSM2_CONF=`realpath "$SOFTHSM2_CONF"`

# execution
set -e

TOKEN_PIN=4321
TOKEN_ID=01
PASS_URI=pass:$TOKEN_PIN
KEY_URI=pkcs11:id=%$TOKEN_ID
KEY_FILE="$TOKEN_DIR"/openssl_test_key
IMPORT_OUT="$TOKEN_DIR"/import.out
INIT_OUT="$TOKEN_DIR"/init.out

if ! softhsm2_tool --init-token --label test0 --slot free --so-pin 12345678 --pin $TOKEN_PIN >"$INIT_OUT" 2>&1; then
	cat "$INIT_OUT"
  cat $TOKEN_DIR/token.log
	exit 1
fi

cat "$INIT_OUT"
cat $TOKEN_DIR/token.log

set -x

openssl genpkey -algorithm ML-DSA-44 -out "$KEY_FILE"

if ! softhsm2_tool --import "$KEY_FILE" --import-type keypair --id $TOKEN_ID --label test_key --token test0 --pin $TOKEN_PIN >"$IMPORT_OUT" 2>&1; then
	cat "$IMPORT_OUT"
  cat $TOKEN_DIR/token.log
	exit 1
fi

cat "$IMPORT_OUT"
cat $TOKEN_DIR/token.log

if ! grep -q "The MLDSA key pair with label=test_key has been imported." "$IMPORT_OUT"; then
	echo "ERROR: Expected MLDSA import success message"
	cat "$IMPORT_OUT"
  cat $TOKEN_DIR/token.log
	exit 1
fi
