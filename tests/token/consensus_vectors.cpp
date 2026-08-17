// Prints consensus-critical constants so the ported (beldex-core-custom) and
// reference (beldex node) implementations can be compared byte-for-byte.
#include "ringct/rctOps.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "common/hex.h"
#include <iostream>

int main()
{
  std::cout << "X_GENERATOR " << tools::type_to_hex(rct::getX()) << "\n";

  // Fixed descriptor -> token id must be identical across implementations.
  cryptonote::tx_extra_token_descriptor_operation tdo{};
  tdo.version = 1;
  tdo.operation_type = cryptonote::token_descriptor_operation_type::register_token;
  tdo.fields = cryptonote::token_field_descriptor;
  tdo.descriptor.version = 1;
  tdo.descriptor.total_max_supply = 21000000;
  tdo.descriptor.current_supply   = 1000000;
  tdo.descriptor.decimal_point    = 8;
  tdo.descriptor.ticker    = "VECT";
  tdo.descriptor.full_name = "Vector Test Token";
  tdo.descriptor.meta_info = "https://example.invalid/meta.json";
  std::cout << "TOKEN_ID_NOSALT " << tools::type_to_hex(cryptonote::get_or_calculate_token_id(tdo)) << "\n";

  tdo.fields |= cryptonote::token_field_token_id_salt;
  tdo.token_id_salt = 42;
  std::cout << "TOKEN_ID_SALT42 " << tools::type_to_hex(cryptonote::get_or_calculate_token_id(tdo)) << "\n";

  // Deterministic commitment vectors (fixed scalars, no RNG).
  rct::key tid{}, r{}, mask{};
  for (int i = 0; i < 32; ++i) { tid.bytes[i] = (unsigned char)(i + 1); r.bytes[i] = (unsigned char)(0x40 ^ i); mask.bytes[i] = (unsigned char)(0x11 * (i % 15)); }
  sc_reduce32(r.bytes); sc_reduce32(mask.bytes);
  rct::key tid_pt = rct::scalarmultBase(tid);           // a valid point from a fixed scalar
  rct::key T = rct::blindTokenId(tid_pt, r);
  std::cout << "BLIND_T " << tools::type_to_hex(T) << "\n";
  std::cout << "COMMIT_C " << tools::type_to_hex(rct::commitToken(mask, T, 123456789ULL)) << "\n";
  return 0;
}
