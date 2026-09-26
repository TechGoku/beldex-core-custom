// Copyright (c) 2026, The Beldex Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

#pragma once

// ---------------------------------------------------------------------------
// Privacy-token zero-knowledge proof STRUCTURES (HF21+).
//
// Split out of token_proofs.h so that ringct/rctTypes.h can pull in just the
// struct definitions it needs for its proof-wrapper types, without a circular
// include.  token_proofs.h includes rctTypes.h (for rct::key); rctTypes.h in
// turn needs these structs.  Routing the structs through this include-free
// header makes the pair order-independent: whichever of the two a translation
// unit reaches first, rctTypes.h emits its wrappers only after this file has
// been processed.
//
// This header assumes rct::key / rct::keyV are already defined -- it is
// included from inside ringct/rctTypes.h, after those types.  Do not include
// it directly; include ringct/rctTypes.h or crypto/token_proofs.h instead.
// ---------------------------------------------------------------------------

#include <stdexcept>
#include "crypto/crypto-ops.h"     // sc_check (canonical-scalar validation at parse time)
#include "serialization/serialization.h" // BEGIN_SERIALIZE_OBJECT, FIELD

namespace crypto {

struct schnorr_sig_s
{
    rct::key y;   // response scalar:  y = r - c*s  (mod l)
    rct::key c;   // challenge scalar: c = H(msg || P || R)

    BEGIN_SERIALIZE_OBJECT()
      FIELD(y)
      FIELD(c)
      if (sc_check(y.bytes) != 0 || sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad schnorr_sig_s serialization (non-canonical scalar)");
    END_SERIALIZE()
};

struct linear_composition_proof_s
{
    rct::key y0;  // response for G component: y0 = r0 - c*a
    rct::key y1;  // response for X component: y1 = r1 - c*b
    rct::key c;   // challenge: c = H(msg || P || R)

    BEGIN_SERIALIZE_OBJECT()
      FIELD(y0)
      FIELD(y1)
      FIELD(c)
      if (sc_check(y0.bytes) != 0 || sc_check(y1.bytes) != 0 || sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad linear_composition_proof_s serialization (non-canonical scalar)");
    END_SERIALIZE()
};

struct double_schnorr_sig_s
{
    rct::key y0;  // response for P0: y0 = r0 - c*s0
    rct::key y1;  // response for P1: y1 = r1 - c*s1
    rct::key c;   // shared challenge: c = H(msg || P0 || P1 || R0 || R1)

    BEGIN_SERIALIZE_OBJECT()
      FIELD(y0)
      FIELD(y1)
      FIELD(c)
      if (sc_check(y0.bytes) != 0 || sc_check(y1.bytes) != 0 || sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad double_schnorr_sig_s serialization (non-canonical scalar)");
    END_SERIALIZE()
};

struct BGE_proof_s
{
    rct::key A;            // commitment A (premultiplied by 1/8 on-chain)
    rct::key B;            // commitment B (premultiplied by 1/8 on-chain)
    rct::keyV Pk;          // per-digit commitments, size = m = ceil(log4(ring_size))
    rct::keyV f;           // polynomial response scalars, size = m * (n-1), n=4
    rct::key  y;           // blinding response for A+xB check
    rct::key  z;           // blinding response for ring check

    BEGIN_SERIALIZE_OBJECT()
      FIELD(A)
      FIELD(B)
      FIELD(Pk)
      FIELD(f)
      FIELD(y)
      FIELD(z)
      if (Pk.empty() || f.size() != Pk.size() * 3)
        throw std::runtime_error("Bad BGE_proof_s serialization");
      if (sc_check(y.bytes) != 0 || sc_check(z.bytes) != 0)
        throw std::runtime_error("Bad BGE_proof_s serialization (non-canonical scalar)");
      for (const auto& fi : f)
        if (sc_check(fi.bytes) != 0)
          throw std::runtime_error("Bad BGE_proof_s serialization (non-canonical f scalar)");
    END_SERIALIZE()
};

struct vector_ug_aggregation_proof_s
{
    rct::keyV amount_commitments_for_rp_aggregation; // E'_j, one per ZY output, premultiplied by 1/8
    rct::keyV y0s; // response scalars (knowledge of amount_j)
    rct::keyV y1s; // response scalars (knowledge of mask_j + w*y'_j)
    rct::key  c;   // common Fiat-Shamir challenge

    BEGIN_SERIALIZE_OBJECT()
      FIELD(amount_commitments_for_rp_aggregation)
      FIELD(y0s)
      FIELD(y1s)
      FIELD(c)
      if (amount_commitments_for_rp_aggregation.empty() ||
          y0s.size() != amount_commitments_for_rp_aggregation.size() ||
          y1s.size() != amount_commitments_for_rp_aggregation.size())
        throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization");
      if (sc_check(c.bytes) != 0)
        throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization (non-canonical c)");
      for (const auto& s : y0s)
        if (sc_check(s.bytes) != 0)
          throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization (non-canonical y0s)");
      for (const auto& s : y1s)
        if (sc_check(s.bytes) != 0)
          throw std::runtime_error("Bad vector_ug_aggregation_proof_s serialization (non-canonical y1s)");
    END_SERIALIZE()
};

} // namespace crypto
