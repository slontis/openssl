/* Shared exact-integer oracle checks, instantiated once per precision. */
static int read_real(FILE *f, FN_DSA_REAL *out)
{
    uint64_t words[ARITH_WORDS];
    unsigned i, j;

    for (i = 0; i < ARITH_WORDS; i++) {
        words[i] = 0;
        for (j = 0; j < 8; j++) {
            int c = fgetc(f);

            if (c == EOF)
                return 0;
            words[i] |= (uint64_t)c << (8 * j);
        }
    }
#if ARITH_WORDS == 1
    *out = (int64_t)words[0];
#else
    *out = (FN_DSA_REAL)(((__uint128_t)words[1] << 64) | words[0]);
#endif
    return 1;
}

static int ARITH_TEST_FN(void)
{
    char *path = test_mk_file_path(data_dir, ARITH_VECTORS);
    FILE *f = NULL;
    FN_DSA_REAL x[7], result;
    unsigned i, count = 0;
    int first, ok = 0;

    if (!TEST_ptr(path) || !TEST_ptr(f = fopen(path, "rb")))
        goto end;
    while ((first = fgetc(f)) != EOF) {
        if (!TEST_int_ne(ungetc(first, f), EOF))
            goto end;
        for (i = 0; i < OSSL_NELEM(x); i++) {
            if (!TEST_true(read_real(f, &x[i])))
                goto end;
        }
        for (i = 0; i < 5; i++) {
            switch (i) {
            case 0:
                result = fxr_add(x[0], x[1]);
                break;
            case 1:
                result = fxr_sub(x[0], x[1]);
                break;
            case 2:
                result = fxr_mul(x[0], x[1]);
                break;
            case 3:
                result = fxr_div(x[0], x[1]);
                break;
            default:
                result = fxr_sqrt((FN_DSA_REAL)fxr_abs(x[0]));
                break;
            }
            if (!TEST_true(fxr_eq(result, x[i + 2]))) {
                TEST_info("Arithmetic case %u, operation %u", count, i);
                goto end;
            }
        }
        if (!TEST_int_eq(fxr_lt(x[0], x[1]), !fxr_ge(x[0], x[1]))
            || !TEST_int_eq(fxr_lt(x[0], x[1]), fxr_gt(x[1], x[0])))
            goto end;
        count++;
    }
    ok = TEST_int_eq(ferror(f), 0) && TEST_uint_gt(count, 0);
    TEST_note("%u exact arithmetic cases, %u.%u format", count,
        ARITH_WORDS * 32, ARITH_WORDS * 32);
end:
    if (f != NULL)
        fclose(f);
    OPENSSL_free(path);
    return ok;
}
