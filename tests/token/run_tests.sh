#!/usr/bin/env bash
# Build and run the HF21 private-token tests under Emscripten + node.
#
#   ./tests/token/run_tests.sh            # from the beldex-core-custom root
#
# Requires an activated emsdk (source <emsdk>/emsdk_env.sh) and node.
#
# token_proofs_test    — round-trip + negative tests for the five proof systems,
#                        the X generator, commitToken/blindTokenId, token-id derivation.
# consensus_vectors    — prints the consensus-critical constants. Build the same
#                        file against the beldex node tree and diff the output;
#                        any difference means this library will produce
#                        transactions the network rejects.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-/tmp/bcc-token-tests}"
mkdir -p "$OUT/obj"
cd "$ROOT"

INC="-I. -Iepee/include -Iexternal -Iexternal/fmt/include -Iexternal/loki-mq
     -Iexternal/oxen-encoding -Icommon -Ivtlogger -Icrypto -Icryptonote_basic
     -Imultisig -Icryptonote_core -Icryptonote_protocol -Iwallet -Irpc -Imnemonics
     -Icontrib/libsodium/include -Icontrib/libsodium/include/sodium"

# -fexceptions must be set at COMPILE time, not just link time, or catch(...)
# in the negative tests will abort instead of catching.
CXXFLAGS="-std=c++17 -w -O1 -fexceptions -DBELDEX_CORE_CUSTOM
          -D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION
          -DBOOST_ASIO_HAS_PTHREADS -DBOOST_HAS_PTHREADS -DBOOST_HAS_THREADS
          -sUSE_BOOST_HEADERS=1"

CFILES="crypto/hash.c crypto/cn_turtle_hash.c crypto/oaes_lib.c crypto/crypto-ops.c
        crypto/crypto-ops-data.c crypto/keccak.c crypto/chacha.c crypto/random.c
        crypto/aesb.c crypto/tree-hash.c crypto/hash-extra-blake.c crypto/blake256.c
        crypto/hash-extra-groestl.c crypto/hash-extra-jh.c crypto/hash-extra-skein.c
        crypto/groestl.c crypto/jh.c crypto/skein.c ringct/rctCryptoOps.c
        common/aligned.c epee/src/memwipe.c contrib/libsodium/src/crypto_verify/verify.c"

CXXFILES="crypto/token_proofs.cpp cryptonote_basic/token_descriptor_operation_utils.cpp
          crypto/crypto.cpp crypto/cn_heavy_hash_hard_arm.cpp
          crypto/cn_heavy_hash_hard_intel.cpp crypto/cn_heavy_hash_soft.cpp
          crypto/slow-hash-dummied.cpp ringct/rctOps.cpp ringct/rctTypes.cpp
          common/util.cpp common/string_util.cpp epee/src/hex.cpp epee/src/mlocker.cpp
          epee/src/wipeable_string.cpp epee/src/string_tools.cpp vtlogger/logger.cpp"

for f in $CFILES;   do emcc -w -O1 $INC -c "$f" -o "$OUT/obj/$(echo "$f" | tr '/' '_').o"; done
for f in $CXXFILES; do em++ $CXXFLAGS $INC -c "$f" -o "$OUT/obj/$(echo "$f" | tr '/' '_').o"; done

for t in token_proofs_test consensus_vectors; do
  em++ $CXXFLAGS $INC -c "tests/token/$t.cpp" -o "$OUT/$t.o"
  em++ -O1 -fexceptions -o "$OUT/$t.js" "$OUT/obj"/*.o "$OUT/$t.o" \
       -sALLOW_MEMORY_GROWTH=1 -sEXIT_RUNTIME=1
  echo "=== $t ==="
  node "$OUT/$t.js"
done
