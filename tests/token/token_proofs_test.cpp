#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "crypto/token_proofs.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "common/hex.h"
#include <iostream>
#include <cassert>

static int fails = 0;

// A verifier that throws on a malformed point is acceptable; one that returns
// true is not. REJECTS() treats both false and an exception as a rejection.
template <class F> static bool REJECTS(F&& f) {
  try { return !f(); } catch (...) { return true; }
}
#define CHECK(cond, name) do { \
  if (cond) std::cout << "  PASS  " << name << "\n"; \
  else { std::cout << "  FAIL  " << name << "\n"; ++fails; } } while(0)

int main()
{
  using namespace rct;

  // ── 1. X generator is deterministic, on-curve, and distinct from G/H ──
  key X  = getX();
  key X2 = getX();
  CHECK(X == X2, "X generator is stable across calls");
  CHECK(isInMainSubgroup(X), "X is in the main subgroup");
  CHECK(!(X == G) && !(X == H), "X differs from G and H");
  std::cout << "        X = " << tools::type_to_hex(X) << "\n";

  // ── 2. blindTokenId / unblind round-trip ──
  key token_id = pkGen();
  key r = skGen();
  key T = blindTokenId(token_id, r);
  key recovered; subKeys(recovered, T, scalarmultX(r));
  CHECK(recovered == token_id, "blindTokenId round-trips (T - r*X == token_id)");
  CHECK(!(T == token_id), "blinding actually changes the id");

  // ── 3. commitToken == amount*T + mask*G ──
  key mask = skGen();
  xmr_amount amt = 1234567890ULL;
  key C = commitToken(mask, T, amt);
  key expect; addKeys(expect, scalarmultKey(T, d2h(amt)), scalarmultBase(mask));
  CHECK(C == expect, "commitToken == amount*T + mask*G");

  // ── 4. Schnorr over G and over X ──
  {
    key msg = skGen(), s = skGen();
    key P = scalarmultBase(s);
    crypto::schnorr_sig_s sig{};
    CHECK(crypto::generate_schnorr_sig(msg, P, s, sig), "schnorr(G) generate");
    CHECK(crypto::verify_schnorr_sig(msg, P, sig), "schnorr(G) verify");
    key bad = skGen();  // different (well-formed) message
    CHECK(REJECTS([&]{ return crypto::verify_schnorr_sig(bad, P, sig); }), "schnorr(G) rejects wrong message");

    key sx = skGen(); key PX = scalarmultX(sx);
    crypto::schnorr_sig_s sigx{};
    CHECK(crypto::generate_schnorr_sig_X(msg, PX, sx, sigx), "schnorr(X) generate");
    CHECK(crypto::verify_schnorr_sig_X(msg, PX, sigx), "schnorr(X) verify");
    CHECK(REJECTS([&]{ return crypto::verify_schnorr_sig_X(msg, P, sigx); }), "schnorr(X) rejects wrong point");
  }

  // ── 5. linear composition proof: P = a*G + b*X ──
  {
    key msg = skGen(), a = skGen(), b = skGen();
    key P; addKeys(P, scalarmultBase(a), scalarmultX(b));
    crypto::linear_composition_proof_s lp{};
    CHECK(crypto::generate_linear_composition_proof(msg, P, a, b, lp), "linear composition generate");
    CHECK(crypto::verify_linear_composition_proof(msg, P, lp), "linear composition verify");
    key badP; addKeys(badP, scalarmultBase(skGen()), scalarmultX(skGen()));
    CHECK(REJECTS([&]{ return crypto::verify_linear_composition_proof(msg, badP, lp); }),
          "linear composition rejects wrong P");
    key badmsg = skGen();
    CHECK(REJECTS([&]{ return crypto::verify_linear_composition_proof(badmsg, P, lp); }),
          "linear composition rejects wrong message");
  }

  // ── 6. double Schnorr: P0 = s0*X, P1 = s1*G ──
  {
    key msg = skGen(), s0 = skGen(), s1 = skGen();
    key P0 = scalarmultX(s0), P1 = scalarmultBase(s1);
    crypto::double_schnorr_sig_s ds{};
    CHECK(crypto::generate_double_schnorr_sig(msg, P0, s0, P1, s1, ds), "double schnorr generate");
    CHECK(crypto::verify_double_schnorr_sig(msg, P0, P1, ds), "double schnorr verify");
    CHECK(REJECTS([&]{ return crypto::verify_double_schnorr_sig(msg, P1, P0, ds); }),
          "double schnorr rejects swapped points");
    key badmsg2 = skGen();
    CHECK(REJECTS([&]{ return crypto::verify_double_schnorr_sig(badmsg2, P0, P1, ds); }),
          "double schnorr rejects wrong message");
  }

  // ── 7. BGE surjection proof across ring sizes ──
  for (size_t ring_size : {1u, 2u, 3u, 4u, 5u, 9u, 16u, 17u, 64u})
  {
    keyV ring; ring.reserve(ring_size);
    for (size_t i = 0; i < ring_size; ++i) ring.push_back(pkGen());
    size_t real = ring_size / 2;
    key blind = skGen();
    key Tb = blindTokenId(ring[real], blind);
    key ctx = skGen();
    crypto::BGE_proof_s bge{};
    bool gen = crypto::generate_BGE_proof(ctx, ring, Tb, blind, real, bge);
    bool ver = gen && crypto::verify_BGE_proof(ctx, ring, Tb, bge);
    CHECK(gen && ver, ("BGE ring_size=" + std::to_string(ring_size)).c_str());
    if (gen) {
      // Use a VALID but wrong curve point: re-blind with a different scalar.
      key badT = blindTokenId(ring[real], skGen());
      bool rejected = false;
      try { rejected = !crypto::verify_BGE_proof(ctx, ring, badT, bge); }
      catch (...) { rejected = true; }
      CHECK(rejected, ("BGE rejects wrong T (ring_size=" + std::to_string(ring_size) + ")").c_str());

      // Wrong context (proof must be bound to the tx)
      bool ctx_rejected = false;
      key badctx = skGen();
      try { ctx_rejected = !crypto::verify_BGE_proof(badctx, ring, Tb, bge); }
      catch (...) { ctx_rejected = true; }
      CHECK(ctx_rejected, ("BGE rejects wrong context (ring_size=" + std::to_string(ring_size) + ")").c_str());

      // Malformed (non-curve) T: must not verify. Throwing is acceptable --
      // consensus gates this earlier via crypto::check_token_key -- but it must
      // never return true.
      key junkT = Tb; junkT.bytes[31] |= 0x40; junkT.bytes[0] ^= 0xff;
      bool junk_ok = true;
      try { junk_ok = crypto::verify_BGE_proof(ctx, ring, junkT, bge); }
      catch (...) { junk_ok = false; }
      CHECK(!junk_ok, ("BGE never accepts malformed T (ring_size=" + std::to_string(ring_size) + ")").c_str());
    }
  }

  // ── 8. vector HG aggregation proof + the commitment relation it bridges ──
  {
    const size_t n = 3;
    key ctx = skGen();
    keyV amounts, real_masks, aux_masks, real_c, aux_c, tags;
    for (size_t j = 0; j < n; ++j) {
      xmr_amount a = 1000ULL * (j + 1);
      key tid = pkGen(), rr = skGen();
      key Tj = blindTokenId(tid, rr);
      key m = skGen(), y = skGen();
      amounts.push_back(d2h(a));
      real_masks.push_back(m);
      aux_masks.push_back(y);
      real_c.push_back(commitToken(m, Tj, a));
      key e; addKeys(e, scalarmultH(d2h(a)), scalarmultBase(y));
      aux_c.push_back(e);
      tags.push_back(Tj);
    }
    crypto::vector_ug_aggregation_proof_s ap{};
    bool gen = crypto::generate_vector_ug_aggregation_proof(ctx, amounts, real_masks, aux_masks, real_c, aux_c, tags, ap);
    CHECK(gen, "vector HG aggregation generate");
    CHECK(gen && crypto::verify_vector_ug_aggregation_proof(ctx, real_c, tags, ap), "vector HG aggregation verify");
    if (gen) {
      keyV bad = real_c; addKeys(bad[0], bad[0], scalarmultBase(skGen()));
      CHECK(REJECTS([&]{ return crypto::verify_vector_ug_aggregation_proof(ctx, bad, tags, ap); }),
            "vector HG rejects wrong commitment");
      key badctx = skGen();
      CHECK(REJECTS([&]{ return crypto::verify_vector_ug_aggregation_proof(badctx, real_c, tags, ap); }),
            "vector HG rejects wrong context");
    }
  }

  // ── 9. token id derivation: deterministic, salt-sensitive, on-curve ──
  {
    cryptonote::tx_extra_token_descriptor_operation tdo{};
    tdo.operation_type = cryptonote::token_descriptor_operation_type::register_token;
    tdo.fields = cryptonote::token_field_descriptor;
    tdo.descriptor.ticker = "TEST";
    tdo.descriptor.full_name = "Test Token";
    tdo.descriptor.total_max_supply = 1000000;
    tdo.descriptor.current_supply = 1000;
    tdo.descriptor.decimal_point = 4;
    auto id1 = cryptonote::get_or_calculate_token_id(tdo);
    auto id2 = cryptonote::get_or_calculate_token_id(tdo);
    CHECK(id1 == id2, "token id derivation is deterministic");
    CHECK(!(id1 == crypto::null_tid), "token id is non-null");
    CHECK(crypto::check_token_key(id1), "token id is a valid curve point");
    CHECK(isInMainSubgroup(tid2rct(id1)), "token id is in the main subgroup");
    std::cout << "        token_id = " << tools::type_to_hex(id1) << "\n";

    tdo.fields |= cryptonote::token_field_token_id_salt;
    tdo.token_id_salt = 7;
    auto id3 = cryptonote::get_or_calculate_token_id(tdo);
    CHECK(!(id3 == id1), "salt changes the token id");

    auto t = tdo; t.descriptor.ticker = "TEST2";
    CHECK(!(cryptonote::get_or_calculate_token_id(t) == id3), "descriptor change changes the token id");
  }

  std::cout << (fails ? "\nFAILURES: " : "\nALL PASSED (failures: ") << fails << ")\n";
  return fails ? 1 : 0;
}
