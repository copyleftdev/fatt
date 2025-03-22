
#ifndef ring_core_generated_PREFIX_SYMBOLS_ASM_H
#define ring_core_generated_PREFIX_SYMBOLS_ASM_H

#if defined(__APPLE__)
#define _ecp_nistz256_point_double _p256_point_double
#define _ecp_nistz256_point_add _p256_point_add
#define _ecp_nistz256_point_add_affine _p256_point_add_affine
#define _ecp_nistz256_ord_mul_mont _p256_scalar_mul_mont
#define _ecp_nistz256_ord_sqr_mont _p256_scalar_sqr_rep_mont
#define _ecp_nistz256_mul_mont _p256_mul_mont
#define _ecp_nistz256_sqr_mont _p256_sqr_mont
#define _adx_bmi2_available _ring_core_0_17_14__adx_bmi2_available
#define _avx2_available _ring_core_0_17_14__avx2_available
#define _CRYPTO_memcmp _ring_core_0_17_14__CRYPTO_memcmp
#define _CRYPTO_poly1305_finish _ring_core_0_17_14__CRYPTO_poly1305_finish
#define _CRYPTO_poly1305_finish_neon _ring_core_0_17_14__CRYPTO_poly1305_finish_neon
#define _CRYPTO_poly1305_init _ring_core_0_17_14__CRYPTO_poly1305_init
#define _CRYPTO_poly1305_init_neon _ring_core_0_17_14__CRYPTO_poly1305_init_neon
#define _CRYPTO_poly1305_update _ring_core_0_17_14__CRYPTO_poly1305_update
#define _CRYPTO_poly1305_update_neon _ring_core_0_17_14__CRYPTO_poly1305_update_neon
#define _ChaCha20_ctr32 _ring_core_0_17_14__ChaCha20_ctr32
#define _ChaCha20_ctr32_avx2 _ring_core_0_17_14__ChaCha20_ctr32_avx2
#define _ChaCha20_ctr32_neon _ring_core_0_17_14__ChaCha20_ctr32_neon
#define _ChaCha20_ctr32_nohw _ring_core_0_17_14__ChaCha20_ctr32_nohw
#define _ChaCha20_ctr32_ssse3 _ring_core_0_17_14__ChaCha20_ctr32_ssse3
#define _ChaCha20_ctr32_ssse3_4x _ring_core_0_17_14__ChaCha20_ctr32_ssse3_4x
#define _LIMB_is_zero _ring_core_0_17_14__LIMB_is_zero
#define _LIMBS_add_mod _ring_core_0_17_14__LIMBS_add_mod
#define _LIMBS_are_zero _ring_core_0_17_14__LIMBS_are_zero
#define _LIMBS_equal _ring_core_0_17_14__LIMBS_equal
#define _LIMBS_less_than _ring_core_0_17_14__LIMBS_less_than
#define _LIMBS_reduce_once _ring_core_0_17_14__LIMBS_reduce_once
#define _LIMBS_select_512_32 _ring_core_0_17_14__LIMBS_select_512_32
#define _LIMBS_shl_mod _ring_core_0_17_14__LIMBS_shl_mod
#define _LIMBS_sub_mod _ring_core_0_17_14__LIMBS_sub_mod
#define _LIMBS_window5_split_window _ring_core_0_17_14__LIMBS_window5_split_window
#define _LIMBS_window5_unsplit_window _ring_core_0_17_14__LIMBS_window5_unsplit_window
#define _LIMB_shr _ring_core_0_17_14__LIMB_shr
#define _OPENSSL_cpuid_setup _ring_core_0_17_14__OPENSSL_cpuid_setup
#define _aes_gcm_dec_kernel _ring_core_0_17_14__aes_gcm_dec_kernel
#define _aes_gcm_dec_update_vaes_avx2 _ring_core_0_17_14__aes_gcm_dec_update_vaes_avx2
#define _aes_gcm_enc_kernel _ring_core_0_17_14__aes_gcm_enc_kernel
#define _aes_gcm_enc_update_vaes_avx2 _ring_core_0_17_14__aes_gcm_enc_update_vaes_avx2
#define _aes_hw_ctr32_encrypt_blocks _ring_core_0_17_14__aes_hw_ctr32_encrypt_blocks
#define _aes_hw_set_encrypt_key _ring_core_0_17_14__aes_hw_set_encrypt_key
#define _aes_hw_set_encrypt_key_alt _ring_core_0_17_14__aes_hw_set_encrypt_key_alt
#define _aes_hw_set_encrypt_key_base _ring_core_0_17_14__aes_hw_set_encrypt_key_base
#define _aes_nohw_ctr32_encrypt_blocks _ring_core_0_17_14__aes_nohw_ctr32_encrypt_blocks
#define _aes_nohw_encrypt _ring_core_0_17_14__aes_nohw_encrypt
#define _aes_nohw_set_encrypt_key _ring_core_0_17_14__aes_nohw_set_encrypt_key
#define _aesni_gcm_decrypt _ring_core_0_17_14__aesni_gcm_decrypt
#define _aesni_gcm_encrypt _ring_core_0_17_14__aesni_gcm_encrypt
#define _bn_from_montgomery_in_place _ring_core_0_17_14__bn_from_montgomery_in_place
#define _bn_gather5 _ring_core_0_17_14__bn_gather5
#define _bn_mul_mont _ring_core_0_17_14__bn_mul_mont
#define _bn_mul_mont_nohw _ring_core_0_17_14__bn_mul_mont_nohw
#define _bn_mul4x_mont _ring_core_0_17_14__bn_mul4x_mont
#define _bn_mulx4x_mont _ring_core_0_17_14__bn_mulx4x_mont
#define _bn_mul8x_mont_neon _ring_core_0_17_14__bn_mul8x_mont_neon
#define _bn_mul4x_mont_gather5 _ring_core_0_17_14__bn_mul4x_mont_gather5
#define _bn_mulx4x_mont_gather5 _ring_core_0_17_14__bn_mulx4x_mont_gather5
#define _bn_neg_inv_mod_r_u64 _ring_core_0_17_14__bn_neg_inv_mod_r_u64
#define _bn_power5_nohw _ring_core_0_17_14__bn_power5_nohw
#define _bn_powerx5 _ring_core_0_17_14__bn_powerx5
#define _bn_scatter5 _ring_core_0_17_14__bn_scatter5
#define _bn_sqr8x_internal _ring_core_0_17_14__bn_sqr8x_internal
#define _bn_sqr8x_mont _ring_core_0_17_14__bn_sqr8x_mont
#define _bn_sqrx8x_internal _ring_core_0_17_14__bn_sqrx8x_internal
#define _bsaes_ctr32_encrypt_blocks _ring_core_0_17_14__bsaes_ctr32_encrypt_blocks
#define _bssl_constant_time_test_conditional_memcpy _ring_core_0_17_14__bssl_constant_time_test_conditional_memcpy
#define _bssl_constant_time_test_conditional_memxor _ring_core_0_17_14__bssl_constant_time_test_conditional_memxor
#define _bssl_constant_time_test_main _ring_core_0_17_14__bssl_constant_time_test_main
#define _chacha20_poly1305_open _ring_core_0_17_14__chacha20_poly1305_open
#define _chacha20_poly1305_open_avx2 _ring_core_0_17_14__chacha20_poly1305_open_avx2
#define _chacha20_poly1305_open_sse41 _ring_core_0_17_14__chacha20_poly1305_open_sse41
#define _chacha20_poly1305_seal _ring_core_0_17_14__chacha20_poly1305_seal
#define _chacha20_poly1305_seal_avx2 _ring_core_0_17_14__chacha20_poly1305_seal_avx2
#define _chacha20_poly1305_seal_sse41 _ring_core_0_17_14__chacha20_poly1305_seal_sse41
#define _ecp_nistz256_mul_mont_adx _ring_core_0_17_14__ecp_nistz256_mul_mont_adx
#define _ecp_nistz256_mul_mont_nohw _ring_core_0_17_14__ecp_nistz256_mul_mont_nohw
#define _ecp_nistz256_ord_mul_mont_adx _ring_core_0_17_14__ecp_nistz256_ord_mul_mont_adx
#define _ecp_nistz256_ord_mul_mont_nohw _ring_core_0_17_14__ecp_nistz256_ord_mul_mont_nohw
#define _ecp_nistz256_ord_sqr_mont_adx _ring_core_0_17_14__ecp_nistz256_ord_sqr_mont_adx
#define _ecp_nistz256_ord_sqr_mont_nohw _ring_core_0_17_14__ecp_nistz256_ord_sqr_mont_nohw
#define _ecp_nistz256_point_add_adx _ring_core_0_17_14__ecp_nistz256_point_add_adx
#define _ecp_nistz256_point_add_nohw _ring_core_0_17_14__ecp_nistz256_point_add_nohw
#define _ecp_nistz256_point_add_affine_adx _ring_core_0_17_14__ecp_nistz256_point_add_affine_adx
#define _ecp_nistz256_point_add_affine_nohw _ring_core_0_17_14__ecp_nistz256_point_add_affine_nohw
#define _ecp_nistz256_point_double_adx _ring_core_0_17_14__ecp_nistz256_point_double_adx
#define _ecp_nistz256_point_double_nohw _ring_core_0_17_14__ecp_nistz256_point_double_nohw
#define _ecp_nistz256_select_w5_avx2 _ring_core_0_17_14__ecp_nistz256_select_w5_avx2
#define _ecp_nistz256_select_w5_nohw _ring_core_0_17_14__ecp_nistz256_select_w5_nohw
#define _ecp_nistz256_select_w7_avx2 _ring_core_0_17_14__ecp_nistz256_select_w7_avx2
#define _ecp_nistz256_select_w7_nohw _ring_core_0_17_14__ecp_nistz256_select_w7_nohw
#define _ecp_nistz256_sqr_mont_adx _ring_core_0_17_14__ecp_nistz256_sqr_mont_adx
#define _ecp_nistz256_sqr_mont_nohw _ring_core_0_17_14__ecp_nistz256_sqr_mont_nohw
#define _fiat_curve25519_adx_mul _ring_core_0_17_14__fiat_curve25519_adx_mul
#define _fiat_curve25519_adx_square _ring_core_0_17_14__fiat_curve25519_adx_square
#define _gcm_ghash_avx _ring_core_0_17_14__gcm_ghash_avx
#define _gcm_ghash_clmul _ring_core_0_17_14__gcm_ghash_clmul
#define _gcm_ghash_neon _ring_core_0_17_14__gcm_ghash_neon
#define _gcm_ghash_vpclmulqdq_avx2_1 _ring_core_0_17_14__gcm_ghash_vpclmulqdq_avx2_1
#define _gcm_gmult_clmul _ring_core_0_17_14__gcm_gmult_clmul
#define _gcm_gmult_neon _ring_core_0_17_14__gcm_gmult_neon
#define _gcm_init_avx _ring_core_0_17_14__gcm_init_avx
#define _gcm_init_clmul _ring_core_0_17_14__gcm_init_clmul
#define _gcm_init_neon _ring_core_0_17_14__gcm_init_neon
#define _gcm_init_vpclmulqdq_avx2 _ring_core_0_17_14__gcm_init_vpclmulqdq_avx2
#define _k25519Precomp _ring_core_0_17_14__k25519Precomp
#define _limbs_mul_add_limb _ring_core_0_17_14__limbs_mul_add_limb
#define _little_endian_bytes_from_scalar _ring_core_0_17_14__little_endian_bytes_from_scalar
#define _ecp_nistz256_neg _ring_core_0_17_14__ecp_nistz256_neg
#define _ecp_nistz256_select_w5 _ring_core_0_17_14__ecp_nistz256_select_w5
#define _ecp_nistz256_select_w7 _ring_core_0_17_14__ecp_nistz256_select_w7
#define _neon_available _ring_core_0_17_14__neon_available
#define _p256_mul_mont _ring_core_0_17_14__p256_mul_mont
#define _p256_point_add _ring_core_0_17_14__p256_point_add
#define _p256_point_add_affine _ring_core_0_17_14__p256_point_add_affine
#define _p256_point_double _ring_core_0_17_14__p256_point_double
#define _p256_point_mul _ring_core_0_17_14__p256_point_mul
#define _p256_point_mul_base _ring_core_0_17_14__p256_point_mul_base
#define _p256_point_mul_base_vartime _ring_core_0_17_14__p256_point_mul_base_vartime
#define _p256_scalar_mul_mont _ring_core_0_17_14__p256_scalar_mul_mont
#define _p256_scalar_sqr_rep_mont _ring_core_0_17_14__p256_scalar_sqr_rep_mont
#define _p256_sqr_mont _ring_core_0_17_14__p256_sqr_mont
#define _p384_elem_div_by_2 _ring_core_0_17_14__p384_elem_div_by_2
#define _p384_elem_mul_mont _ring_core_0_17_14__p384_elem_mul_mont
#define _p384_elem_neg _ring_core_0_17_14__p384_elem_neg
#define _p384_elem_sub _ring_core_0_17_14__p384_elem_sub
#define _p384_point_add _ring_core_0_17_14__p384_point_add
#define _p384_point_double _ring_core_0_17_14__p384_point_double
#define _p384_point_mul _ring_core_0_17_14__p384_point_mul
#define _p384_scalar_mul_mont _ring_core_0_17_14__p384_scalar_mul_mont
#define _openssl_poly1305_neon2_addmulmod _ring_core_0_17_14__openssl_poly1305_neon2_addmulmod
#define _openssl_poly1305_neon2_blocks _ring_core_0_17_14__openssl_poly1305_neon2_blocks
#define _sha256_block_data_order _ring_core_0_17_14__sha256_block_data_order
#define _sha256_block_data_order_avx _ring_core_0_17_14__sha256_block_data_order_avx
#define _sha256_block_data_order_ssse3 _ring_core_0_17_14__sha256_block_data_order_ssse3
#define _sha256_block_data_order_hw _ring_core_0_17_14__sha256_block_data_order_hw
#define _sha256_block_data_order_neon _ring_core_0_17_14__sha256_block_data_order_neon
#define _sha256_block_data_order_nohw _ring_core_0_17_14__sha256_block_data_order_nohw
#define _sha512_block_data_order _ring_core_0_17_14__sha512_block_data_order
#define _sha512_block_data_order_avx _ring_core_0_17_14__sha512_block_data_order_avx
#define _sha512_block_data_order_hw _ring_core_0_17_14__sha512_block_data_order_hw
#define _sha512_block_data_order_neon _ring_core_0_17_14__sha512_block_data_order_neon
#define _sha512_block_data_order_nohw _ring_core_0_17_14__sha512_block_data_order_nohw
#define _vpaes_ctr32_encrypt_blocks _ring_core_0_17_14__vpaes_ctr32_encrypt_blocks
#define _vpaes_encrypt _ring_core_0_17_14__vpaes_encrypt
#define _vpaes_encrypt_key_to_bsaes _ring_core_0_17_14__vpaes_encrypt_key_to_bsaes
#define _vpaes_set_encrypt_key _ring_core_0_17_14__vpaes_set_encrypt_key
#define _x25519_NEON _ring_core_0_17_14__x25519_NEON
#define _x25519_fe_invert _ring_core_0_17_14__x25519_fe_invert
#define _x25519_fe_isnegative _ring_core_0_17_14__x25519_fe_isnegative
#define _x25519_fe_mul_ttt _ring_core_0_17_14__x25519_fe_mul_ttt
#define _x25519_fe_neg _ring_core_0_17_14__x25519_fe_neg
#define _x25519_fe_tobytes _ring_core_0_17_14__x25519_fe_tobytes
#define _x25519_ge_double_scalarmult_vartime _ring_core_0_17_14__x25519_ge_double_scalarmult_vartime
#define _x25519_ge_frombytes_vartime _ring_core_0_17_14__x25519_ge_frombytes_vartime
#define _x25519_ge_scalarmult_base _ring_core_0_17_14__x25519_ge_scalarmult_base
#define _x25519_ge_scalarmult_base_adx _ring_core_0_17_14__x25519_ge_scalarmult_base_adx
#define _x25519_public_from_private_generic_masked _ring_core_0_17_14__x25519_public_from_private_generic_masked
#define _x25519_sc_mask _ring_core_0_17_14__x25519_sc_mask
#define _x25519_sc_muladd _ring_core_0_17_14__x25519_sc_muladd
#define _x25519_sc_reduce _ring_core_0_17_14__x25519_sc_reduce
#define _x25519_scalar_mult_adx _ring_core_0_17_14__x25519_scalar_mult_adx
#define _x25519_scalar_mult_generic_masked _ring_core_0_17_14__x25519_scalar_mult_generic_masked

#else
#define ecp_nistz256_point_double p256_point_double
#define ecp_nistz256_point_add p256_point_add
#define ecp_nistz256_point_add_affine p256_point_add_affine
#define ecp_nistz256_ord_mul_mont p256_scalar_mul_mont
#define ecp_nistz256_ord_sqr_mont p256_scalar_sqr_rep_mont
#define ecp_nistz256_mul_mont p256_mul_mont
#define ecp_nistz256_sqr_mont p256_sqr_mont
#define adx_bmi2_available ring_core_0_17_14__adx_bmi2_available
#define avx2_available ring_core_0_17_14__avx2_available
#define CRYPTO_memcmp ring_core_0_17_14__CRYPTO_memcmp
#define CRYPTO_poly1305_finish ring_core_0_17_14__CRYPTO_poly1305_finish
#define CRYPTO_poly1305_finish_neon ring_core_0_17_14__CRYPTO_poly1305_finish_neon
#define CRYPTO_poly1305_init ring_core_0_17_14__CRYPTO_poly1305_init
#define CRYPTO_poly1305_init_neon ring_core_0_17_14__CRYPTO_poly1305_init_neon
#define CRYPTO_poly1305_update ring_core_0_17_14__CRYPTO_poly1305_update
#define CRYPTO_poly1305_update_neon ring_core_0_17_14__CRYPTO_poly1305_update_neon
#define ChaCha20_ctr32 ring_core_0_17_14__ChaCha20_ctr32
#define ChaCha20_ctr32_avx2 ring_core_0_17_14__ChaCha20_ctr32_avx2
#define ChaCha20_ctr32_neon ring_core_0_17_14__ChaCha20_ctr32_neon
#define ChaCha20_ctr32_nohw ring_core_0_17_14__ChaCha20_ctr32_nohw
#define ChaCha20_ctr32_ssse3 ring_core_0_17_14__ChaCha20_ctr32_ssse3
#define ChaCha20_ctr32_ssse3_4x ring_core_0_17_14__ChaCha20_ctr32_ssse3_4x
#define LIMB_is_zero ring_core_0_17_14__LIMB_is_zero
#define LIMBS_add_mod ring_core_0_17_14__LIMBS_add_mod
#define LIMBS_are_zero ring_core_0_17_14__LIMBS_are_zero
#define LIMBS_equal ring_core_0_17_14__LIMBS_equal
#define LIMBS_less_than ring_core_0_17_14__LIMBS_less_than
#define LIMBS_reduce_once ring_core_0_17_14__LIMBS_reduce_once
#define LIMBS_select_512_32 ring_core_0_17_14__LIMBS_select_512_32
#define LIMBS_shl_mod ring_core_0_17_14__LIMBS_shl_mod
#define LIMBS_sub_mod ring_core_0_17_14__LIMBS_sub_mod
#define LIMBS_window5_split_window ring_core_0_17_14__LIMBS_window5_split_window
#define LIMBS_window5_unsplit_window ring_core_0_17_14__LIMBS_window5_unsplit_window
#define LIMB_shr ring_core_0_17_14__LIMB_shr
#define OPENSSL_cpuid_setup ring_core_0_17_14__OPENSSL_cpuid_setup
#define aes_gcm_dec_kernel ring_core_0_17_14__aes_gcm_dec_kernel
#define aes_gcm_dec_update_vaes_avx2 ring_core_0_17_14__aes_gcm_dec_update_vaes_avx2
#define aes_gcm_enc_kernel ring_core_0_17_14__aes_gcm_enc_kernel
#define aes_gcm_enc_update_vaes_avx2 ring_core_0_17_14__aes_gcm_enc_update_vaes_avx2
#define aes_hw_ctr32_encrypt_blocks ring_core_0_17_14__aes_hw_ctr32_encrypt_blocks
#define aes_hw_set_encrypt_key ring_core_0_17_14__aes_hw_set_encrypt_key
#define aes_hw_set_encrypt_key_alt ring_core_0_17_14__aes_hw_set_encrypt_key_alt
#define aes_hw_set_encrypt_key_base ring_core_0_17_14__aes_hw_set_encrypt_key_base
#define aes_nohw_ctr32_encrypt_blocks ring_core_0_17_14__aes_nohw_ctr32_encrypt_blocks
#define aes_nohw_encrypt ring_core_0_17_14__aes_nohw_encrypt
#define aes_nohw_set_encrypt_key ring_core_0_17_14__aes_nohw_set_encrypt_key
#define aesni_gcm_decrypt ring_core_0_17_14__aesni_gcm_decrypt
#define aesni_gcm_encrypt ring_core_0_17_14__aesni_gcm_encrypt
#define bn_from_montgomery_in_place ring_core_0_17_14__bn_from_montgomery_in_place
#define bn_gather5 ring_core_0_17_14__bn_gather5
#define bn_mul_mont ring_core_0_17_14__bn_mul_mont
#define bn_mul_mont_nohw ring_core_0_17_14__bn_mul_mont_nohw
#define bn_mul4x_mont ring_core_0_17_14__bn_mul4x_mont
#define bn_mulx4x_mont ring_core_0_17_14__bn_mulx4x_mont
#define bn_mul8x_mont_neon ring_core_0_17_14__bn_mul8x_mont_neon
#define bn_mul4x_mont_gather5 ring_core_0_17_14__bn_mul4x_mont_gather5
#define bn_mulx4x_mont_gather5 ring_core_0_17_14__bn_mulx4x_mont_gather5
#define bn_neg_inv_mod_r_u64 ring_core_0_17_14__bn_neg_inv_mod_r_u64
#define bn_power5_nohw ring_core_0_17_14__bn_power5_nohw
#define bn_powerx5 ring_core_0_17_14__bn_powerx5
#define bn_scatter5 ring_core_0_17_14__bn_scatter5
#define bn_sqr8x_internal ring_core_0_17_14__bn_sqr8x_internal
#define bn_sqr8x_mont ring_core_0_17_14__bn_sqr8x_mont
#define bn_sqrx8x_internal ring_core_0_17_14__bn_sqrx8x_internal
#define bsaes_ctr32_encrypt_blocks ring_core_0_17_14__bsaes_ctr32_encrypt_blocks
#define bssl_constant_time_test_conditional_memcpy ring_core_0_17_14__bssl_constant_time_test_conditional_memcpy
#define bssl_constant_time_test_conditional_memxor ring_core_0_17_14__bssl_constant_time_test_conditional_memxor
#define bssl_constant_time_test_main ring_core_0_17_14__bssl_constant_time_test_main
#define chacha20_poly1305_open ring_core_0_17_14__chacha20_poly1305_open
#define chacha20_poly1305_open_avx2 ring_core_0_17_14__chacha20_poly1305_open_avx2
#define chacha20_poly1305_open_sse41 ring_core_0_17_14__chacha20_poly1305_open_sse41
#define chacha20_poly1305_seal ring_core_0_17_14__chacha20_poly1305_seal
#define chacha20_poly1305_seal_avx2 ring_core_0_17_14__chacha20_poly1305_seal_avx2
#define chacha20_poly1305_seal_sse41 ring_core_0_17_14__chacha20_poly1305_seal_sse41
#define ecp_nistz256_mul_mont_adx ring_core_0_17_14__ecp_nistz256_mul_mont_adx
#define ecp_nistz256_mul_mont_nohw ring_core_0_17_14__ecp_nistz256_mul_mont_nohw
#define ecp_nistz256_ord_mul_mont_adx ring_core_0_17_14__ecp_nistz256_ord_mul_mont_adx
#define ecp_nistz256_ord_mul_mont_nohw ring_core_0_17_14__ecp_nistz256_ord_mul_mont_nohw
#define ecp_nistz256_ord_sqr_mont_adx ring_core_0_17_14__ecp_nistz256_ord_sqr_mont_adx
#define ecp_nistz256_ord_sqr_mont_nohw ring_core_0_17_14__ecp_nistz256_ord_sqr_mont_nohw
#define ecp_nistz256_point_add_adx ring_core_0_17_14__ecp_nistz256_point_add_adx
#define ecp_nistz256_point_add_nohw ring_core_0_17_14__ecp_nistz256_point_add_nohw
#define ecp_nistz256_point_add_affine_adx ring_core_0_17_14__ecp_nistz256_point_add_affine_adx
#define ecp_nistz256_point_add_affine_nohw ring_core_0_17_14__ecp_nistz256_point_add_affine_nohw
#define ecp_nistz256_point_double_adx ring_core_0_17_14__ecp_nistz256_point_double_adx
#define ecp_nistz256_point_double_nohw ring_core_0_17_14__ecp_nistz256_point_double_nohw
#define ecp_nistz256_select_w5_avx2 ring_core_0_17_14__ecp_nistz256_select_w5_avx2
#define ecp_nistz256_select_w5_nohw ring_core_0_17_14__ecp_nistz256_select_w5_nohw
#define ecp_nistz256_select_w7_avx2 ring_core_0_17_14__ecp_nistz256_select_w7_avx2
#define ecp_nistz256_select_w7_nohw ring_core_0_17_14__ecp_nistz256_select_w7_nohw
#define ecp_nistz256_sqr_mont_adx ring_core_0_17_14__ecp_nistz256_sqr_mont_adx
#define ecp_nistz256_sqr_mont_nohw ring_core_0_17_14__ecp_nistz256_sqr_mont_nohw
#define fiat_curve25519_adx_mul ring_core_0_17_14__fiat_curve25519_adx_mul
#define fiat_curve25519_adx_square ring_core_0_17_14__fiat_curve25519_adx_square
#define gcm_ghash_avx ring_core_0_17_14__gcm_ghash_avx
#define gcm_ghash_clmul ring_core_0_17_14__gcm_ghash_clmul
#define gcm_ghash_neon ring_core_0_17_14__gcm_ghash_neon
#define gcm_ghash_vpclmulqdq_avx2_1 ring_core_0_17_14__gcm_ghash_vpclmulqdq_avx2_1
#define gcm_gmult_clmul ring_core_0_17_14__gcm_gmult_clmul
#define gcm_gmult_neon ring_core_0_17_14__gcm_gmult_neon
#define gcm_init_avx ring_core_0_17_14__gcm_init_avx
#define gcm_init_clmul ring_core_0_17_14__gcm_init_clmul
#define gcm_init_neon ring_core_0_17_14__gcm_init_neon
#define gcm_init_vpclmulqdq_avx2 ring_core_0_17_14__gcm_init_vpclmulqdq_avx2
#define k25519Precomp ring_core_0_17_14__k25519Precomp
#define limbs_mul_add_limb ring_core_0_17_14__limbs_mul_add_limb
#define little_endian_bytes_from_scalar ring_core_0_17_14__little_endian_bytes_from_scalar
#define ecp_nistz256_neg ring_core_0_17_14__ecp_nistz256_neg
#define ecp_nistz256_select_w5 ring_core_0_17_14__ecp_nistz256_select_w5
#define ecp_nistz256_select_w7 ring_core_0_17_14__ecp_nistz256_select_w7
#define neon_available ring_core_0_17_14__neon_available
#define p256_mul_mont ring_core_0_17_14__p256_mul_mont
#define p256_point_add ring_core_0_17_14__p256_point_add
#define p256_point_add_affine ring_core_0_17_14__p256_point_add_affine
#define p256_point_double ring_core_0_17_14__p256_point_double
#define p256_point_mul ring_core_0_17_14__p256_point_mul
#define p256_point_mul_base ring_core_0_17_14__p256_point_mul_base
#define p256_point_mul_base_vartime ring_core_0_17_14__p256_point_mul_base_vartime
#define p256_scalar_mul_mont ring_core_0_17_14__p256_scalar_mul_mont
#define p256_scalar_sqr_rep_mont ring_core_0_17_14__p256_scalar_sqr_rep_mont
#define p256_sqr_mont ring_core_0_17_14__p256_sqr_mont
#define p384_elem_div_by_2 ring_core_0_17_14__p384_elem_div_by_2
#define p384_elem_mul_mont ring_core_0_17_14__p384_elem_mul_mont
#define p384_elem_neg ring_core_0_17_14__p384_elem_neg
#define p384_elem_sub ring_core_0_17_14__p384_elem_sub
#define p384_point_add ring_core_0_17_14__p384_point_add
#define p384_point_double ring_core_0_17_14__p384_point_double
#define p384_point_mul ring_core_0_17_14__p384_point_mul
#define p384_scalar_mul_mont ring_core_0_17_14__p384_scalar_mul_mont
#define openssl_poly1305_neon2_addmulmod ring_core_0_17_14__openssl_poly1305_neon2_addmulmod
#define openssl_poly1305_neon2_blocks ring_core_0_17_14__openssl_poly1305_neon2_blocks
#define sha256_block_data_order ring_core_0_17_14__sha256_block_data_order
#define sha256_block_data_order_avx ring_core_0_17_14__sha256_block_data_order_avx
#define sha256_block_data_order_ssse3 ring_core_0_17_14__sha256_block_data_order_ssse3
#define sha256_block_data_order_hw ring_core_0_17_14__sha256_block_data_order_hw
#define sha256_block_data_order_neon ring_core_0_17_14__sha256_block_data_order_neon
#define sha256_block_data_order_nohw ring_core_0_17_14__sha256_block_data_order_nohw
#define sha512_block_data_order ring_core_0_17_14__sha512_block_data_order
#define sha512_block_data_order_avx ring_core_0_17_14__sha512_block_data_order_avx
#define sha512_block_data_order_hw ring_core_0_17_14__sha512_block_data_order_hw
#define sha512_block_data_order_neon ring_core_0_17_14__sha512_block_data_order_neon
#define sha512_block_data_order_nohw ring_core_0_17_14__sha512_block_data_order_nohw
#define vpaes_ctr32_encrypt_blocks ring_core_0_17_14__vpaes_ctr32_encrypt_blocks
#define vpaes_encrypt ring_core_0_17_14__vpaes_encrypt
#define vpaes_encrypt_key_to_bsaes ring_core_0_17_14__vpaes_encrypt_key_to_bsaes
#define vpaes_set_encrypt_key ring_core_0_17_14__vpaes_set_encrypt_key
#define x25519_NEON ring_core_0_17_14__x25519_NEON
#define x25519_fe_invert ring_core_0_17_14__x25519_fe_invert
#define x25519_fe_isnegative ring_core_0_17_14__x25519_fe_isnegative
#define x25519_fe_mul_ttt ring_core_0_17_14__x25519_fe_mul_ttt
#define x25519_fe_neg ring_core_0_17_14__x25519_fe_neg
#define x25519_fe_tobytes ring_core_0_17_14__x25519_fe_tobytes
#define x25519_ge_double_scalarmult_vartime ring_core_0_17_14__x25519_ge_double_scalarmult_vartime
#define x25519_ge_frombytes_vartime ring_core_0_17_14__x25519_ge_frombytes_vartime
#define x25519_ge_scalarmult_base ring_core_0_17_14__x25519_ge_scalarmult_base
#define x25519_ge_scalarmult_base_adx ring_core_0_17_14__x25519_ge_scalarmult_base_adx
#define x25519_public_from_private_generic_masked ring_core_0_17_14__x25519_public_from_private_generic_masked
#define x25519_sc_mask ring_core_0_17_14__x25519_sc_mask
#define x25519_sc_muladd ring_core_0_17_14__x25519_sc_muladd
#define x25519_sc_reduce ring_core_0_17_14__x25519_sc_reduce
#define x25519_scalar_mult_adx ring_core_0_17_14__x25519_scalar_mult_adx
#define x25519_scalar_mult_generic_masked ring_core_0_17_14__x25519_scalar_mult_generic_masked

#endif
#endif
