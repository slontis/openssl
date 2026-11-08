/*
 * ePrint 2026/1531, Appendix A, Algorithm 11 (ApproxExp).
 * The listed integer coefficients and Horner recurrence approximate
 * 2^63 * ccs * exp(-x), for 0 <= x <= ln(2) and 0 <= ccs <= 1.
 */
static inline int64_t fxr_expm_p63(FN_DSA_REAL x, FN_DSA_REAL ccs)
{
    static const uint64_t c[] = {
        UINT64_C(0x00000004741183A3), UINT64_C(0x00000036548CFC06),
        UINT64_C(0x0000024FDCBF140A), UINT64_C(0x0000171D939DE045),
        UINT64_C(0x0000D00CF58F6F84), UINT64_C(0x000680681CF796E3),
        UINT64_C(0x002D82D8305B0FEA), UINT64_C(0x011111110E066FD0),
        UINT64_C(0x0555555555070F00), UINT64_C(0x155555555581FF00),
        UINT64_C(0x400000000002B400), UINT64_C(0x7FFFFFFFFFFF4800),
        UINT64_C(0x8000000000000000)};
    uint64_t z = fxr_q63(x), y = c[0];
    unsigned i;
    for (i = 1; i < 13; i++)
        y = c[i] - (uint64_t)(((__uint128_t)z * y) >> 63);
    z = fxr_q63(ccs);
    return (int64_t)(((__uint128_t)z * y) >> 63);
}
