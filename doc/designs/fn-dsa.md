# FN-DSA key and codec design

The key lifecycle follows ML-DSA's separation between a seed prekey and an
initialized key. `include/crypto/fn_dsa.h` declares an opaque `FN_DSA_KEY` and
per-variant `FN_DSA_PARAMS`. All arithmetic and key code live in the single
`crypto/fn_dsa` directory. Its `fn_dsa_key.c` owns the retained seed,
public encoding, and expanded private cache. Provider key-management code lives
in `providers/implementations/keymgmt/fn_dsa_kmgmt.c`; codecs live alongside
`ml_dsa_codecs.c` in `providers/implementations/encode_decode`.

## Generation and import

`ossl_fn_dsa_set_prekey()` copies a 32-byte seed into secure allocation.
`ossl_fn_dsa_generate_key()` expands that seed through the fixed-point backend,
preserving it alongside the initialized key. Without an input seed, generation
obtains a new 32-byte seed from the private DRBG in the key's library context.
The property query is used for the SHAKE-256 fetch. This development profile
feeds the seed directly into SHAKE-256, without padding to the older 48-byte
compatibility-test seed length. Alignment with normative FN-DSA seed expansion
remains necessary before interoperable standard-conforming keys are claimed.

Generation uses ML-DSA's seed parameter pattern, with no signature-style
deterministic flag. The generation context copies its seed and can generate
the same complete key repeatedly. A zero-length seed parameter clears that
configured seed, restoring fresh random generation for subsequent calls.
Other nonzero lengths must be exactly 32 bytes. Invalid parameters leave the
previously configured seed intact.

Provider `fromdata` accepts seed, public encoding, and internal private cache.
When a seed is provided, it regenerates the key and checks any accompanying
public or private value with `CRYPTO_memcmp()`. A mismatch fails and resets the
key. Private-cache import validates the private equation and bounds and derives
the public encoding. Public import checks the parameter-set header and canonical
coefficient encoding. Initialized keys are immutable.

## Ownership

The seed and expanded private cache use secure allocations and are cleared on
reset/free. Private duplication copies both into independent allocations.
Public-only duplication and export omit private material. Seed prekeys cannot
be duplicated before expansion, following the ML-DSA lifecycle. Failure during
generation clears the staged seed and cache rather than leaving a partial key.

## Encoding and loading

The dedicated `fn_dsa_codecs.c` exports key-object interfaces matching ML-DSA's
codec pattern. The PKCS#8 decoder creates a seed prekey. The provider's `load`
callback expands it before returning a usable key to EVP. Thus a PKCS#8 round
trip restores the full key, rather than only preserving an arbitrary byte string.

Seed-only loading is slow because it runs complete key generation, including
the NTRU solver, on each load or import. Applications should reuse an initialized
`EVP_PKEY` for repeated signing: its expanded cache avoids repeating generation.

The payload is exactly 32 raw seed bytes, following the provisional IETF draft.
No expanded private-key wire format or ML-DSA CHOICE encoding is added.
Cache-only keys cannot be encoded as PKCS#8 without their original seed.
Nonempty output-format overrides fail rather than silently emitting a seed.

SPKI contains the canonical public bytes. Its internal parser deliberately uses
OpenSSL's existing `ossl_d2i_X509_PUBKEY_INTERNAL()` parser: calling the public
SPKI parser from a provider decoder could recursively fetch that same decoder.
The shared OpenSSL frameworks provide DER/PEM and encrypted PKCS#8 support;
there are no algorithm-specific ASN.1 templates or legacy ASN.1 methods.

## Integration and tests

The central object database owns names and numeric identifiers. The parameter
name generator defines `OSSL_PKEY_PARAM_FN_DSA_SEED` with the value `seed`, just
as for ML-DSA. `no-fn-dsa` excludes key management, codecs, and arithmetic from
the library while retaining object recognition. Native tests cover seed-based
generation, import/export, duplication selections, mismatch rejection, and
regeneration through plain/encrypted DER and PEM. Compatibility tests retain
their separate 48-byte deterministic fixtures unchanged.

The default provider exposes the paper's 64.64 sampler through
`fn_dsa_sig.c`, using ML-DSA's provider interfaces as the reference. One-shot
and buffered update/final operations are supported. Signatures use fresh
randomness by default. Pure message framing follows ML-DSA exactly:
`0x00 || one-byte context length || context || message`, with up to 255 context
bytes. The key module builds the bounded prefix and the backend absorbs it
separately from the message, avoiding an extra full-message allocation.
Context and test entropy parameters freeze on the first update and are
copied with a duplicated signature context.

Signing stays randomized in ordinary builds: the backend obtains a new
40-byte nonce and 48-byte private sampler seed for each operation. A
`deterministic` parameter is not advertised or accepted. No new key/message
randomness derivation is added. This follows NIST's published randomized-only
position for FN-DSA rather than copying ML-DSA's deterministic signing mode.

`enable-fn-dsa-test-entropy` is a separate feature disabled by default. It guards
the provider's entropy buffer, parameter handling and internal test entry points
with `OPENSSL_NO_FN_DSA_TEST_ENTROPY`. Test builds accept exactly 88 controlled
bytes (nonce followed by sampler seed) on signing contexts for test keys only.
Production builds reject that parameter; verification always rejects it.
Configure disables the hook when FN-DSA or tests are disabled. Key generation's
32-byte seed parameter remains independent of this test-only feature.
Explicit external digests, prehash modes and raw framing overrides are rejected.
`EVP_SIGNATURE-FN-DSA(7)` documents these operations and the
remaining normative specification and validation work. Native key-generation and codec tests are regression tests,
not NIST FN-DSA KATs or a complete timing/precision security evaluation.


## Fixed-point square root

`fxr_sqrt()` uses the reciprocal-square-root Newton iteration described in
[ePrint 2026/1531, Section 3.4](https://eprint.iacr.org/2026/1531):

    y <- y * (3 - x*y*y) / 2
    sqrt(x) = x*y

The interface retains 64.64 or 32.32 values. Inside this one operation, integer
normalization represents `x` in `[1, 4)` with 126 or 62 fractional bits. This
preserves enough significant bits for exact final rounding across the entire
nonnegative input range. The even normalization exponent is recovered with six
fixed bit-scan steps, without a lookup table or a leading-zero intrinsic.
A zero input is replaced by one during computation and masked to zero at the end.

The initial approximation is `(35 - 5*x)/32`, evaluated with shifts. In exact
arithmetic its relative error is less than `1/8`: the extrema of
`(35 - 5*x)*sqrt(x)/32` on `[1, 4]` occur at `1`, `7/3` and `4`. The shift rounding
adds less than two normalized ulps to the initial reciprocal square root.
The code always performs six Newton iterations for the 64.64 interface and five
for 32.32, irrespective of the operand.

For the error bound, let `u = 2^-p`, where `p` is 126 or 62, and let
`eta = 1 - y*sqrt(x)`. The exact iteration maps `eta` to
`3*eta^2/2 - eta^3/2`. Each normalized product is truncated. The first product loses less than `u`.
Multiplication by `x < 4` and its own truncation make the total error in
`x*y*y` less than `5*u`; halving then rounds by at most `u/2`.
Since the iterates satisfy `0 < y <= 1 + 8*u`, the final product perturbs `y`
by less than `3*u`, or `eta` by less than `6*u`.
A conservative directed bound is therefore

    b0 = 1/8 + 8*u
    b_next = (3*b*b + b*b*b)/2 + 8*u

`tools/check_sqrt_bounds.py` evaluates this upper bound using only integers and
upward rounding. It checks that the final relative error is less than `9*u`.
Including the last truncated `x*y` product, the approximation before conversion
to an integer root is within `2^-26` output ulps for 64.64, and `2^-10` for 32.32.
Both are less than `1/4` ulp.

Let `N = raw_input * 2^fraction_bits` and let `q` be that approximation truncated
to an integer. The nearest integer to `sqrt(N)` is then either `q` or `q+1`.
The correct choice is `q+1` exactly when `N - q*q > q`; an exact half-way case
cannot occur for integral `N`. The signed remainder has magnitude below `2^98`
or `2^50`, respectively, so unsigned arithmetic modulo the storage width
recovers it exactly even though the full square and radicand are wider than
that storage. This final correction preserves the exact integer oracle results.

These bounds concern arithmetic and rounding. Constant-time behavior still
requires checking generated code and instruction timing for each supported
target; a fixed iteration count alone does not establish it.


## Digest ownership

A key retains the immutable fetched SHAKE-256 `EVP_MD`, as in the ML-DSA key
layer. Duplication takes a reference instead of fetching it again. Each operation
creates its own initialized `EVP_MD_CTX` and passes that borrowed context down
to the core; the core never owns or frees it. Hashing the message and initializing
the sampler reuse that context sequentially, with digest reinitialization at the
stream boundary. Key-generation rejection consumes a single uninterrupted stream.
An explicit operation property override fetches its digest once at the operation
boundary. Raw internal entry points likewise fetch once before passing the context
down. Public-key reconstruction uses only arithmetic and does not initialize SHAKE.
