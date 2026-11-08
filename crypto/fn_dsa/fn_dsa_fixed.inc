/* Scalar-specialized native FN-DSA kernels. */
#ifdef FN_DSA_KEYGEN
#include "fn_dsa_keygen_core.inc"
#else
#include "fn_dsa_sign_core.inc"
#endif
