/** 
 * @file
 * @brief 단위테스트에서 사용되는 각종 샘플 정보들의 헤더 파일
 * @date 2020-05-26
 * @author gyun
 */


#ifndef V2X_SW_TEST_VECTORS_H
#define V2X_SW_TEST_VECTORS_H

// 시스템 헤더 파일
#include <stddef.h>
#include <stdint.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal-defines.h"
#include "dot2-internal-types.h"


/*
 * 테스트용 RCA 인증서 정보
 */
extern const char *g_tv_rca_cert;
extern size_t g_tv_rca_cert_size;
extern unsigned int g_tv_rca_cert_type;
extern unsigned int g_tv_rca_cert_issuer_id_type;
extern unsigned int g_tv_rca_cert_id_type;
extern const char *g_tv_rca_cert_id_name;
extern const char *g_tv_rca_cert_craca_id;
extern unsigned int g_tv_rca_cert_crl_series;
extern uint64_t g_tv_rca_cert_valid_start;
extern uint64_t g_tv_rca_cert_valid_end;
extern unsigned int g_tv_rca_cert_valid_region_type;
extern bool g_tv_rca_cert_enc_pub_key_present;
extern unsigned int g_tv_rca_cert_key_indicator_type;
extern const char *g_tv_rca_cert_key_indicator;
extern const char *g_tv_rca_cert_pub_key_uncomp;
extern const char *g_tv_rca_cert_sig_r;
extern const char *g_tv_rca_cert_sig_s;
extern const char *g_tv_rca_cert_h;
extern const char *g_tv_rca_cert_tbs;
extern size_t g_tv_rca_cert_tbs_size;

/*
 * 테스트용 ICA 인증서 정보
 */
extern const char *g_tv_ica_cert;
extern size_t g_tv_ica_cert_size;
extern unsigned int g_tv_ica_cert_type;
extern unsigned int g_tv_ica_cert_issuer_id_type;
extern const char *g_tv_ica_cert_issuer_h8;
extern unsigned int g_tv_ica_cert_id_type;
extern const char *g_tv_ica_cert_id_name;
extern const char *g_tv_ica_cert_craca_id;
extern unsigned int g_tv_ica_cert_crl_series;
extern uint64_t g_tv_ica_cert_valid_start;
extern uint64_t g_tv_ica_cert_valid_end;
extern unsigned int g_tv_ica_cert_valid_region_type;
extern unsigned int g_tv_ica_cert_valid_region_num;
extern uint16_t g_tv_ica_cert_valid_region[7];
extern bool g_tv_ica_cert_enc_pub_key_present;
extern unsigned int g_tv_ica_cert_key_indicator_type;
extern const char *g_tv_ica_cert_key_indicator;
extern const char *g_tv_ica_cert_pub_key_uncomp;
extern const char *g_tv_ica_cert_sig_r;
extern const char *g_tv_ica_cert_sig_s;
extern const char *g_tv_ica_cert_h;
extern const char *g_tv_ica_cert_tbs;
extern size_t g_tv_ica_cert_tbs_size;

/*
 * 테스트용 PCA/ACA 인증서 정보
 */
extern const char *g_tv_pca_cert;
extern size_t g_tv_pca_cert_size;
extern unsigned int g_tv_pca_cert_type;
extern unsigned int g_tv_pca_cert_issuer_id_type;
extern const char *g_tv_pca_cert_issuer_h8;
extern unsigned int g_tv_pca_cert_id_type;
extern const char *g_tv_pca_cert_id_name;
extern const char *g_tv_pca_cert_craca_id;
extern unsigned int g_tv_pca_cert_crl_series;
extern uint64_t g_tv_pca_cert_valid_start;
extern uint64_t g_tv_pca_cert_valid_end;
extern unsigned int g_tv_pca_cert_valid_region_type;
extern unsigned int g_tv_pca_cert_valid_region_num;
extern uint16_t g_tv_pca_cert_valid_region[7];
extern bool g_tv_pca_cert_enc_pub_key_present;
extern unsigned int g_tv_pca_cert_key_indicator_type;
extern const char *g_tv_pca_cert_key_indicator;
extern const char *g_tv_pca_cert_pub_key_uncomp;
extern const char *g_tv_pca_cert_enc_pub_key;
extern const char *g_tv_pca_cert_enc_pub_key_uncomp;
extern const char *g_tv_pca_cert_sig_r;
extern const char *g_tv_pca_cert_sig_s;
extern const char *g_tv_pca_cert_h;
extern const char *g_tv_pca_cert_tbs;
extern size_t g_tv_pca_cert_tbs_size;

/*
 * 테스트용 ECA 인증서 정보
 */
extern const char *g_tv_eca_cert;
extern size_t g_tv_eca_cert_size;
extern unsigned int g_tv_eca_cert_type;
extern unsigned int g_tv_eca_cert_issuer_id_type;
extern const char *g_tv_eca_cert_issuer_h8;
extern unsigned int g_tv_eca_cert_id_type;
extern const char *g_tv_eca_cert_id_name;
extern const char *g_tv_eca_cert_craca_id;
extern unsigned int g_tv_eca_cert_crl_series;
extern uint64_t g_tv_eca_cert_valid_start;
extern uint64_t g_tv_eca_cert_valid_end;
extern unsigned int g_tv_eca_cert_valid_region_type;
extern unsigned int g_tv_eca_cert_valid_region_num;
extern uint16_t g_tv_eca_cert_valid_region[7];
extern bool g_tv_eca_cert_enc_pub_key_present;
extern unsigned int g_tv_eca_cert_key_indicator_type;
extern const char *g_tv_eca_cert_key_indicator;
extern const char *g_tv_eca_cert_pub_key_uncomp;
extern const char *g_tv_eca_cert_enc_pub_key;
extern const char *g_tv_eca_cert_enc_pub_key_uncomp;
extern const char *g_tv_eca_cert_sig_r;
extern const char *g_tv_eca_cert_sig_s;
extern const char *g_tv_eca_cert_h;
extern const char *g_tv_eca_cert_tbs;
extern size_t g_tv_eca_cert_tbs_size;

/*
 * 테스트용 RA 인증서 정보
 */
extern const char *g_tv_ra_cert;
extern size_t g_tv_ra_cert_size;
extern unsigned int g_tv_ra_cert_type;
extern unsigned int g_tv_ra_cert_issuer_id_type;
extern const char *g_tv_ra_cert_issuer_h8;
extern unsigned int g_tv_ra_cert_id_type;
extern const char *g_tv_ra_cert_id_name;
extern const char *g_tv_ra_cert_craca_id;
extern unsigned int g_tv_ra_cert_crl_series;
extern uint64_t g_tv_ra_cert_valid_start;
extern uint64_t g_tv_ra_cert_valid_end;
extern unsigned int g_tv_ra_cert_valid_region_type;
extern unsigned int g_tv_ra_cert_valid_region_num;
extern uint16_t g_tv_ra_cert_valid_region[7];
extern bool g_tv_ra_cert_enc_pub_key_present;
extern unsigned int g_tv_ra_cert_key_indicator_type;
extern const char *g_tv_ra_cert_key_indicator;
extern const char *g_tv_ra_cert_pub_key_uncomp;
extern const char *g_tv_ra_cert_enc_pub_key;
extern const char *g_tv_ra_cert_enc_pub_key_uncomp;
extern const char *g_tv_ra_cert_sig_r;
extern const char *g_tv_ra_cert_sig_s;
extern const char *g_tv_ra_cert_h;
extern const char *g_tv_ra_cert_tbs;
extern size_t g_tv_ra_cert_tbs_size;


/*
 * Compressed 서명 테스트벡터
 */
extern const char *g_tv_comp_sign_tbs_1;
extern size_t g_tv_comp_sign_tbs_size_1;
extern const char *g_tv_comp_sign_R_1;
extern const char *g_tv_comp_sign_s_1;
extern const char *g_tv_comp_sign_signer_h_1;
extern const char *g_tv_comp_sign_signer_pub_key_1;
extern const char *g_tv_comp_sign_tbs_2;
extern size_t g_tv_comp_sign_tbs_size_2;
extern const char *g_tv_comp_sign_R_2;
extern const char *g_tv_comp_sign_s_2;
extern const char *g_tv_comp_sign_signer_h_2;
extern const char *g_tv_comp_sign_signer_pub_key_2;
extern const char *g_tv_comp_sign_tbs_3;
extern size_t g_tv_comp_sign_tbs_size_3;
extern const char *g_tv_comp_sign_R_3;
extern const char *g_tv_comp_sign_s_3;
extern const char *g_tv_comp_sign_signer_h_3;
extern const char *g_tv_comp_sign_signer_pub_key_3;
extern const char *g_tv_comp_sign_tbs_4;
extern size_t g_tv_comp_sign_tbs_size_4;
extern const char *g_tv_comp_sign_R_4;
extern const char *g_tv_comp_sign_s_4;
extern const char *g_tv_comp_sign_signer_h_4;
extern const char *g_tv_comp_sign_signer_pub_key_4;
extern const char *g_tv_comp_sign_tbs_5;
extern size_t g_tv_comp_sign_tbs_size_5;
extern const char *g_tv_comp_sign_R_5;
extern const char *g_tv_comp_sign_s_5;
extern const char *g_tv_comp_sign_signer_h_5;
extern const char *g_tv_comp_sign_signer_pub_key_5;

/*
 * Uncompressed 서명 테스트벡터
 */
extern const char *g_tv_uncomp_sign_tbs_1;
extern size_t g_tv_uncomp_sign_tbs_size_1;
extern const char *g_tv_uncomp_sign_R_1;
extern const char *g_tv_uncomp_sign_s_1;
extern const char *g_tv_uncomp_sign_signer_h_1;
extern const char *g_tv_uncomp_sign_signer_pub_key_1;
extern const char *g_tv_uncomp_sign_tbs_2;
extern size_t g_tv_uncomp_sign_tbs_size_2;
extern const char *g_tv_uncomp_sign_R_2;
extern const char *g_tv_uncomp_sign_s_2;
extern const char *g_tv_uncomp_sign_signer_h_2;
extern const char *g_tv_uncomp_sign_signer_pub_key_2;
extern const char *g_tv_uncomp_sign_tbs_3;
extern size_t g_tv_uncomp_sign_tbs_size_3;
extern const char *g_tv_uncomp_sign_R_3;
extern const char *g_tv_uncomp_sign_s_3;
extern const char *g_tv_uncomp_sign_signer_h_3;
extern const char *g_tv_uncomp_sign_signer_pub_key_3;
extern const char *g_tv_uncomp_sign_tbs_4;
extern size_t g_tv_uncomp_sign_tbs_size_4;
extern const char *g_tv_uncomp_sign_R_4;
extern const char *g_tv_uncomp_sign_s_4;
extern const char *g_tv_uncomp_sign_signer_h_4;
extern const char *g_tv_uncomp_sign_signer_pub_key_4;
extern const char *g_tv_uncomp_sign_tbs_5;
extern size_t g_tv_uncomp_sign_tbs_size_5;
extern const char *g_tv_uncomp_sign_R_5;
extern const char *g_tv_uncomp_sign_s_5;
extern const char *g_tv_uncomp_sign_signer_h_5;
extern const char *g_tv_uncomp_sign_signer_pub_key_5;

/*
 * x-only 서명 테스트벡터
 */
extern const char *g_tv_xonly_sign_tbs_1;
extern size_t g_tv_xonly_sign_tbs_size_1;
extern const char *g_tv_xonly_sign_R_1;
extern const char *g_tv_xonly_sign_s_1;
extern const char *g_tv_xonly_sign_signer_h_1;
extern const char *g_tv_xonly_sign_signer_pub_key_1;
extern const char *g_tv_xonly_sign_tbs_2;
extern size_t g_tv_xonly_sign_tbs_size_2;
extern const char *g_tv_xonly_sign_R_2;
extern const char *g_tv_xonly_sign_s_2;
extern const char *g_tv_xonly_sign_signer_h_2;
extern const char *g_tv_xonly_sign_signer_pub_key_2;
extern const char *g_tv_xonly_sign_tbs_3;
extern size_t g_tv_xonly_sign_tbs_size_3;
extern const char *g_tv_xonly_sign_R_3;
extern const char *g_tv_xonly_sign_s_3;
extern const char *g_tv_xonly_sign_signer_h_3;
extern const char *g_tv_xonly_sign_signer_pub_key_3;
extern const char *g_tv_xonly_sign_tbs_4;
extern size_t g_tv_xonly_sign_tbs_size_4;
extern const char *g_tv_xonly_sign_R_4;
extern const char *g_tv_xonly_sign_s_4;
extern const char *g_tv_xonly_sign_signer_h_4;
extern const char *g_tv_xonly_sign_signer_pub_key_4;
extern const char *g_tv_xonly_sign_tbs_5;
extern size_t g_tv_xonly_sign_tbs_size_5;
extern const char *g_tv_xonly_sign_R_5;
extern const char *g_tv_xonly_sign_s_5;
extern const char *g_tv_xonly_sign_signer_h_5;
extern const char *g_tv_xonly_sign_signer_pub_key_5;


/*
 * CMHF 테스트벡터
 */
extern const char *g_tv_cmhf_issuer;
extern int g_tv_cmhf_issuer_size;
extern const char *g_tv_cmhf_issuer_h;
extern const char *g_tv_cmhf_app_cert_0;
extern int g_tv_cmhf_app_cert_size_0;
extern const char *g_tv_cmhf_app_cert_init_priv_key_0;
extern const char *g_tv_cmhf_app_cert_recon_priv_0;
extern const char *g_tv_cmhf_app_cert_priv_key_0;
extern const char *g_tv_cmhf_app_cert_key_cmhf_name_0;
extern uint8_t g_tv_cmhf_app_cert_key_cmhf_0;
extern int g_tv_cmhf_app_cert_key_cmhf_size_0;

/*
 * 인증서 번들 테스트벡터 #1
 */
extern const char *g_tv_bundle_0_rca;
extern const char *g_tv_bundle_0_rca_h;
extern const char *g_tv_bundle_0_rca_pub_key;
extern size_t g_tv_bundle_0_rca_size;
extern const char *g_tv_bundle_0_ica;
extern const char *g_tv_bundle_0_ica_h;
extern const char *g_tv_bundle_0_ica_pub_key;
extern size_t g_tv_bundle_0_ica_size;
extern const char *g_tv_bundle_0_pca;
extern const char *g_tv_bundle_0_pca_h;
extern const char *g_tv_bundle_0_pca_pub_key;
extern size_t g_tv_bundle_0_pca_size;
extern const char *g_tv_bundle_0_eca;
extern const char *g_tv_bundle_0_eca_h;
extern const char *g_tv_bundle_0_eca_pub_key;
extern size_t g_tv_bundle_0_eca_size;
extern const char *g_tv_bundle_0_ra;
extern const char *g_tv_bundle_0_ra_h;
extern const char *g_tv_bundle_0_ra_pub_key;
extern size_t g_tv_bundle_0_ra_size;
extern const char *g_tv_bundle_0_app_cert_0_init_priv_key;
extern const char *g_tv_bundle_0_app_cert_0_recon_priv;
extern const char *g_tv_bundle_0_app_cert_0_recon_pub;
extern const char *g_tv_bundle_0_app_cert_0_priv_key;
extern const char *g_tv_bundle_0_app_cert_0_pub_key;
extern const char *g_tv_bundle_0_app_cert_0;
extern const char *g_tv_bundle_0_app_cert_0_h;
extern const char *g_tv_bundle_0_app_cert_0_tbs_h;
extern size_t g_tv_bundle_0_app_cert_0_size;
extern const char *g_tv_bundle_0_app_cert_0_cmhf_name;
extern const char *g_tv_bundle_0_app_cert_0_cmhf;
extern size_t g_tv_bundle_0_app_cert_0_cmhf_size;
extern const char *g_tv_bundle_0_app_cert_1_init_priv_key;
extern const char *g_tv_bundle_0_app_cert_1_recon_priv;
extern const char *g_tv_bundle_0_app_cert_1_recon_pub;
extern const char *g_tv_bundle_0_app_cert_1_priv_key;
extern const char *g_tv_bundle_0_app_cert_1_pub_key;
extern const char *g_tv_bundle_0_app_cert_1;
extern const char *g_tv_bundle_0_app_cert_1_h;
extern const char *g_tv_bundle_0_app_cert_1_tbs_h;
extern size_t g_tv_bundle_0_app_cert_1_size;
extern const char *g_tv_bundle_0_app_cert_1_cmhf_name;
extern const char *g_tv_bundle_0_app_cert_1_cmhf;
extern size_t g_tv_bundle_0_app_cert_1_cmhf_size;
extern const char *g_tv_bundle_0_pseudonym_13a_seed_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_expansion_key;
extern const char *g_tv_bundle_0_pseudonym_13a_0_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_0_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_0_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_0_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_0_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_0_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_0_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_0_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_1_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_1_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_1_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_1_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_1_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_1_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_1_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_1_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_2_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_2_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_2_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_2_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_2_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_2_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_2_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_2_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_3_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_3_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_3_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_3_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_3_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_3_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_3_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_3_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_4_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_4_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_4_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_4_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_4_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_4_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_4_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_4_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_5_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_5_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_5_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_5_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_5_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_5_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_5_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_5_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_6_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_6_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_6_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_6_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_6_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_6_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_6_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_6_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_7_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_7_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_7_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_7_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_7_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_7_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_7_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_7_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_8_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_8_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_8_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_8_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_8_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_8_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_8_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_8_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_9_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_9_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_9_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_9_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_9_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_9_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_9_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_9_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_a_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_a_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_a_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_a_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_a_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_a_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_a_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_a_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_b_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_b_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_b_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_b_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_b_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_b_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_b_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_b_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_c_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_c_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_c_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_c_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_c_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_c_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_c_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_c_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_d_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_d_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_d_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_d_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_d_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_d_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_d_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_d_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_e_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_e_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_e_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_e_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_e_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_e_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_e_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_e_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_f_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_f_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_f_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_f_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_f_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_f_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_f_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_f_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_10_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_10_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_10_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_10_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_10_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_10_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_10_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_10_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_11_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_11_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_11_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_11_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_11_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_11_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_11_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_11_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_12_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_12_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_12_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_12_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_12_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_12_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_12_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_12_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_13_recon_priv;
extern const char *g_tv_bundle_0_pseudonym_13a_13_recon_pub;
extern const char *g_tv_bundle_0_pseudonym_13a_13_priv_key;
extern const char *g_tv_bundle_0_pseudonym_13a_13_pub_key;
extern const char *g_tv_bundle_0_pseudonym_13a_13_cert;
extern const char *g_tv_bundle_0_pseudonym_13a_13_cert_h;
extern const char *g_tv_bundle_0_pseudonym_13a_13_cert_tbs_h;
extern size_t g_tv_bundle_0_pseudonym_13a_13_cert_size;
extern const char *g_tv_bundle_0_pseudonym_13a_cmhf_name;
extern size_t g_tv_bundle_0_pseudonym_13a_cmhf_size;
extern const char *g_tv_bundle_0_pseudonym_13a_cmhf;
void Dot2Test_Add_CertBundle_0_SCCCerts();
void Dot2Test_Load_CertBundle_0_AppCMHFs();
void Dot2Test_Load_CertBundle_0_PseudonymCMHFs();
bool Dot2Test_Check_CertBundle_0_AppCert_0_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry);
bool Dot2Test_Check_CertBundle_0_AppCert_1_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry);
bool Dot2Test_Check_CertBundle_0_PseudonymCert_13a_CMHSetEntry(struct Dot2RotateCMHSetEntry *cmh_entry);


/*
 * 인증서 번들 테스트벡터 #2
 */
extern const char *g_tv_bundle_1_rca;
extern const char *g_tv_bundle_1_rca_h;
extern const char *g_tv_bundle_1_rca_pub_key;
extern int g_tv_bundle_1_rca_size;
extern const char *g_tv_bundle_1_ica;
extern const char *g_tv_bundle_1_ica_h;
extern const char *g_tv_bundle_1_ica_pub_key;
extern int g_tv_bundle_1_ica_size;
extern const char *g_tv_bundle_1_pca;
extern const char *g_tv_bundle_1_pca_h;
extern const char *g_tv_bundle_1_pca_pub_key;
extern int g_tv_bundle_1_pca_size;
extern const char *g_tv_bundle_1_eca;
extern const char *g_tv_bundle_1_eca_h;
extern const char *g_tv_bundle_1_eca_pub_key;
extern int g_tv_bundle_1_eca_size;
extern const char *g_tv_bundle_1_ra;
extern const char *g_tv_bundle_1_ra_h;
extern const char *g_tv_bundle_1_ra_pub_key;
extern int g_tv_bundle_1_ra_size;
extern const char *g_tv_bundle_1_enrol_cert_0_init_priv_key;
extern const char *g_tv_bundle_1_enrol_cert_0_recon_priv;
extern const char *g_tv_bundle_1_enrol_cert_0_recon_pub;
extern const char *g_tv_bundle_1_enrol_cert_0_priv_key;
extern const char *g_tv_bundle_1_enrol_cert_0_pub_key;
extern const char *g_tv_bundle_1_enrol_cert_0;
extern const char *g_tv_bundle_1_enrol_cert_0_h;
extern const char *g_tv_bundle_1_enrol_cert_0_tbs_h;
extern int g_tv_bundle_1_enrol_cert_0_size;
extern const char *g_tv_bundle_1_enrol_cert_0_cmhf_name;
extern const char *g_tv_bundle_1_enrol_cert_0_cmhf;
extern int g_tv_bundle_1_enrol_cert_0_cmhf_size;
extern const char *g_tv_bundle_1_app_cert_0_init_priv_key;
extern const char *g_tv_bundle_1_app_cert_0_recon_priv;
extern const char *g_tv_bundle_1_app_cert_0_recon_pub;
extern const char *g_tv_bundle_1_app_cert_0_priv_key;
extern const char *g_tv_bundle_1_app_cert_0_pub_key;
extern const char *g_tv_bundle_1_app_cert_0;
extern const char *g_tv_bundle_1_app_cert_0_h;
extern const char *g_tv_bundle_1_app_cert_0_tbs_h;
extern int g_tv_bundle_1_app_cert_0_size;
extern const char *g_tv_bundle_1_app_cert_0_cmhf_name;
extern const char *g_tv_bundle_1_app_cert_0_cmhf;
extern int g_tv_bundle_1_app_cert_0_cmhf_size;
extern const char *g_tv_bundle_1_app_cert_1_init_priv_key;
extern const char *g_tv_bundle_1_app_cert_1_recon_priv;
extern const char *g_tv_bundle_1_app_cert_1_recon_pub;
extern const char *g_tv_bundle_1_app_cert_1_priv_key;
extern const char *g_tv_bundle_1_app_cert_1_pub_key;
extern const char *g_tv_bundle_1_app_cert_1;
extern const char *g_tv_bundle_1_app_cert_1_h;
extern const char *g_tv_bundle_1_app_cert_1_tbs_h;
extern int g_tv_bundle_1_app_cert_1_size;
extern const char *g_tv_bundle_1_app_cert_1_cmhf_name;
extern const char *g_tv_bundle_1_app_cert_1_cmhf;
extern int g_tv_bundle_1_app_cert_1_cmhf_size;
extern const char *g_tv_bundle_1_id_cert_0_seed_priv_key;
extern const char *g_tv_bundle_1_id_cert_0_expansion_key;
extern const char *g_tv_bundle_1_id_cert_0_recon_priv;
extern const char *g_tv_bundle_1_id_cert_0_recon_pub;
extern const char *g_tv_bundle_1_id_cert_0_priv_key;
extern const char *g_tv_bundle_1_id_cert_0_pub_key;
extern const char *g_tv_bundle_1_id_cert_0;
extern const char *g_tv_bundle_1_id_cert_0_h;
extern const char *g_tv_bundle_1_id_cert_0_tbs_h;
extern int g_tv_bundle_1_id_cert_0_size;
extern const char *g_tv_bundle_1_id_cert_0_cmhf_name;
extern const char *g_tv_bundle_1_id_cert_0_cmhf;
extern int g_tv_bundle_1_id_cert_0_cmhf_size;
extern const char *g_tv_bundle_1_id_cert_1_seed_priv_key;
extern const char *g_tv_bundle_1_id_cert_1_expansion_key;
extern const char *g_tv_bundle_1_id_cert_1_recon_priv;
extern const char *g_tv_bundle_1_id_cert_1_recon_pub;
extern const char *g_tv_bundle_1_id_cert_1_priv_key;
extern const char *g_tv_bundle_1_id_cert_1_pub_key;
extern const char *g_tv_bundle_1_id_cert_1;
extern const char *g_tv_bundle_1_id_cert_1_h;
extern const char *g_tv_bundle_1_id_cert_1_tbs_h;
extern int g_tv_bundle_1_id_cert_1_size;
extern const char *g_tv_bundle_1_id_cert_1_cmhf_name;
extern const char *g_tv_bundle_1_id_cert_1_cmhf;
extern int g_tv_bundle_1_id_cert_1_cmhf_size;
void Dot2Test_Load_CertBundle_1_EnrolCMHF();
void Dot2Test_Add_CertBundle_1_SCCCerts();
void Dot2Test_Load_CertBundle_1_AppCMHFs();
bool Dot2Test_Check_CertBundle_1_EnrolCert_0_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry);
bool Dot2Test_Check_CertBundle_1_AppCert_0_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry);
bool Dot2Test_Check_CertBundle_1_AppCert_1_CMHEntry(struct Dot2SequentialCMHEntry *cmh_entry);
bool Dot2Test_Check_CertBundle_1_IdCert_0_CMHSetEntry(struct Dot2RotateCMHSetEntry *cmh_entry);



/*
 * Security profile 관련 단위테스트를 위한 정의
 */
#define SEC_PROFILE_PSID (32U) ///< Security profile에 연관된 PSID
#define SEC_PROFILE_TX_GEN_TIME_HDR_PRESENT (true)
#define SEC_PROFILE_TX_EXP_TIME_HDR_PRESENT (true)
#define SEC_PROFILE_TX_GEN_LOCATION_HDR_PRESENT (true)
#define SEC_PROFILE_TX_SPDU_LIFETIME (1000000ULL) ///< SPDU 수명 (마이크로초)
#define SEC_PROFILE_TX_MIN_INTER_CERT_TIME (450000ULL) ///< 인증서 서명 주기 (마이크로초)
#define SEC_PROFILE_TX_SIGN_TYPE (kDot2SecProfileSign_Compressed)
#define SEC_PROFLIE_TX_ECP_FORMAT (kDot2SecProfileEcPointFormat_Compressed)
#define SEC_PROFILE_TX_SIGNINIG_INTERNVAL (100U) ///< 서명 주기 (밀리초)
#define SEC_PROFILE_RX_VERIFY_DATA (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_IN_PAST (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_VALIDITY_PERIOD (1000000ULL) ///< SPDU가 유효하다고 판정되는 수신시각과 생성시각(과거)의 차이 (마이크로초 단위)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_IN_FUTURE (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD (1000000ULL) ///< SPDU가 유효하다고 판정되는 수신시각과 생성시각(미래)의 차이 (마이크로초 단위)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_SRC (kDot2RelevanceTimeSource_SecurityHeader)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_EXP_TIME (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_EXP_TIME_SRC (kDot2RelevanceTimeSource_SecurityHeader)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION_DISTANCE (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_VALID_DISTANCE (10000U) ///< SPDU가 유효하다고 판정되는 수신지점과 생성지점의 차이 (미터단위)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION_SRC (kDot2ConsistencyLocationSource_SecurityHeader)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_CERT_EXPIRY (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION (true)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_OVERDUE_CRL_TOLERANCE (10U) ///< Overdue CRL tolerance (초)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_SPDU_1_GEN_TIME (10000001000000ULL)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_SPDU_2_GEN_TIME (10000001100000ULL)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_VALID_PERIOD (1000000000ULL)
#define SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_TEST_CNT (12)


/**
 * @brief Security profile - rx - relevance check - replay check 테스트 벡터 형식
 */
struct Dot2Test_SecProfileReplayTestVector
{
  Dot2Time64 spdu_1_gen_time; ///< SPDU1의 생성 시각
  Dot2Time64 spdu_2_gen_time; ///< SPDU2의 생성 시각
  struct Dot2Signature spdu_1_sign; ///< SPDU1의 서명
  struct Dot2Signature spdu_2_sign; ///< SPDU2의 서명
  bool identical; ///< 두 SPDU가 동일한지 여부
};


/*
 * Unsecured 메시지 샘플 데이터
 */
extern uint8_t g_simple_unsecured_msg[];
extern size_t g_simple_unsecured_msg_size;
extern uint8_t *g_simple_unsecured_payload;
extern size_t g_simple_unsecured_payload_size;
extern uint8_t g_invalid_proto_ver_unsecured_msg[];
extern size_t g_invalid_proto_ver_unsecured_msg_size;
extern uint8_t g_shortest_unsecured_msg[];
extern size_t g_shortest_unsecured_msg_size;
extern size_t g_shortest_unsecured_payload_size;
extern uint8_t g_longest_unsecured_msg[];
extern size_t g_longest_unsecured_msg_size;
extern uint8_t *g_longest_unsecured_payload;
extern size_t g_longest_unsecured_payload_size;


/*
 * SignedData 메시지 샘플 데이터
 */
extern uint8_t g_sample_signed_data_payload[];
extern size_t g_sample_signed_data_payload_size;
extern uint8_t g_sample_min_header_signed_data[];
extern size_t g_sample_min_header_signed_data_size;
extern uint8_t g_sample_min_header_signed_data_sign_R[];
extern uint8_t g_sample_min_header_signed_data_sign_s[];
extern uint8_t g_sample_min_header_signed_data_h_tbs[];
extern uint8_t g_sample_max_header_signed_data[];
extern size_t g_sample_max_header_signed_data_size;
extern uint8_t g_sample_max_header_signed_data_sign_R[];
extern uint8_t g_sample_max_header_signed_data_sign_s[];
extern uint64_t g_sample_max_header_signed_data_gen_time;
extern uint64_t g_sample_max_header_signed_data_exp_time;
extern Dot2Latitude g_sample_max_header_signed_data_gen_lat;
extern Dot2Longitude g_sample_max_header_signed_data_gen_lon;
extern uint8_t g_sample_uncompressed_signed_data[];
extern size_t g_sample_uncompressed_signed_data_size;
extern uint8_t g_sample_uncompressed_signed_data_sign_R[];
extern uint8_t g_sample_uncompressed_signed_data_sign_s[];
extern uint8_t g_sample_x_only_signed_data[];
extern size_t g_sample_x_only_signed_data_size;
extern uint8_t g_sample_x_only_signed_data_sign_R[];
extern uint8_t g_sample_x_only_signed_data_sign_s[];
extern uint8_t g_sample_digest_signed_data[];
extern size_t g_sample_digest_signed_data_size;
extern uint8_t g_sample_rse_0_cert_signed_data[];
extern size_t g_sample_rse_0_cert_signed_data_size;
extern uint8_t g_sample_rse_0_digest_signed_data[];
extern size_t g_sample_rse_0_digest_signed_data_size;
extern uint8_t g_sample_rse_1_cert_signed_data[];
extern size_t g_sample_rse_1_cert_signed_data_size;
extern uint8_t g_sample_rse_1_digest_signed_data[];
extern size_t g_sample_rse_1_digest_signed_data_size;
extern uint8_t g_sample_rse_2_cert_signed_data[];
extern size_t g_sample_rse_2_cert_signed_data_size;
extern uint8_t g_sample_rse_2_digest_signed_data[];
extern size_t g_sample_rse_2_digest_signed_data_size;
extern uint8_t g_sample_rse_3_cert_signed_data[];
extern size_t g_sample_rse_3_cert_signed_data_size;
extern uint8_t g_sample_rse_3_digest_signed_data[];
extern size_t g_sample_rse_3_digest_signed_data_size;
extern uint8_t g_sample_rse_4_cert_signed_data[];
extern size_t g_sample_rse_4_cert_signed_data_size;
extern uint8_t g_sample_rse_4_digest_signed_data[];
extern size_t g_sample_rse_4_digest_signed_data_size;
extern uint8_t g_sample_obu_10a_0_cert_signed_bsm[];
extern size_t g_sample_obu_10a_0_cert_signed_bsm_size;
extern uint8_t g_sample_obu_10a_0_cert_signed_pvd[];
extern uint8_t g_sample_obu_10a_0_digest_signed_bsm[];
extern size_t g_sample_obu_10a_0_digest_signed_bsm_size;
extern size_t g_sample_obu_10a_0_cert_signed_pvd_size;
extern uint8_t g_sample_obu_10a_0_digest_signed_pvd[];
extern size_t g_sample_obu_10a_0_digest_signed_pvd_size;
extern uint8_t g_sample_obu_10b_0_cert_signed_bsm[];
extern size_t g_sample_obu_10b_0_cert_signed_bsm_size;
extern uint8_t g_sample_obu_10b_0_digest_signed_bsm[];
extern size_t g_sample_obu_10b_0_digest_signed_bsm_size;
extern uint8_t g_sample_obu_10b_0_cert_signed_pvd[];
extern size_t g_sample_obu_10b_0_cert_signed_pvd_size;
extern uint8_t g_sample_obu_10b_0_digest_signed_pvd[];
extern size_t g_sample_obu_10b_0_digest_signed_pvd_size;
extern uint8_t g_sample_obu_10c_0_cert_signed_bsm[];
extern size_t g_sample_obu_10c_0_cert_signed_bsm_size;
extern uint8_t g_sample_obu_10c_0_digest_signed_bsm[];
extern size_t g_sample_obu_10c_0_digest_signed_bsm_size;
extern uint8_t g_sample_obu_10c_0_cert_signed_pvd[];
extern size_t g_sample_obu_10c_0_cert_signed_pvd_size;
extern uint8_t g_sample_obu_10c_0_digest_signed_pvd[];
extern size_t g_sample_obu_10c_0_digest_signed_pvd_size;
extern uint8_t g_sample_obu_10d_0_cert_signed_bsm[];
extern size_t g_sample_obu_10d_0_cert_signed_bsm_size;
extern uint8_t g_sample_obu_10d_0_digest_signed_bsm[];
extern size_t g_sample_obu_10d_0_digest_signed_bsm_size;
extern uint8_t g_sample_obu_10d_0_cert_signed_pvd[];
extern size_t g_sample_obu_10d_0_cert_signed_pvd_size;
extern uint8_t g_sample_obu_10d_0_digest_signed_pvd[];
extern size_t g_sample_obu_10d_0_digest_signed_pvd_size;
extern uint8_t g_sample_obu_10e_0_cert_signed_bsm[];
extern size_t g_sample_obu_10e_0_cert_signed_bsm_size;
extern uint8_t g_sample_obu_10e_0_digest_signed_bsm[];
extern size_t g_sample_obu_10e_0_digest_signed_bsm_size;
extern uint8_t g_sample_obu_10e_0_cert_signed_pvd[];
extern size_t g_sample_obu_10e_0_cert_signed_pvd_size;
extern uint8_t g_sample_obu_10e_0_digest_signed_pvd[];
extern size_t g_sample_obu_10e_0_digest_signed_pvd_size;

/*
 * SPDU consistency check 테스트 벡터
 */
extern uint8_t g_sample_spdu_consistency_check_no_gentime_exptime[];
extern size_t g_sample_spdu_consistency_check_no_gentime_exptime_size;
extern uint8_t g_sample_spdu_consistency_check_gentime_only[];
extern size_t g_sample_spdu_consistency_check_gentime_only_size;
extern uint8_t g_sample_spdu_consistency_check_exptime_only[];
extern size_t g_sample_spdu_consistency_check_exptime_only_size;
extern uint8_t g_sample_spdu_consistency_check_gentime_exptime[];
extern size_t g_sample_spdu_consistency_check_gentime_exptime_size;
extern uint8_t g_sample_spdu_consistency_check_gentime_is_future_than_exptime[];
extern size_t g_sample_spdu_consistency_check_gentime_is_future_than_exptime_size;
extern uint8_t g_sample_spdu_consistency_check_exptime_is_earlier_than_cert_valid_start[];
extern size_t g_sample_spdu_consistency_check_exptime_is_earlier_than_cert_valid_start_size;
extern uint8_t g_sample_spdu_consistency_check_exptime_is_later_than_cert_valid_end[];
extern size_t g_sample_spdu_consistency_check_exptime_is_later_than_cert_valid_end_size;
extern uint8_t g_sample_spdu_consistency_check_gentime_is_earlier_than_cert_valid_start[];
extern size_t g_sample_spdu_consistency_check_gentime_is_earlier_than_cert_valid_start_size;
extern uint8_t g_sample_spdu_consistency_check_gentime_is_later_than_cert_valid_end[];
extern size_t g_sample_spdu_consistency_check_gentime_is_later_than_cert_valid_end_size;
extern uint8_t g_sample_spdu_consistency_check_no_gen_location[];
extern size_t g_sample_spdu_consistency_check_no_gen_location_size;
extern uint8_t g_sample_spdu_consistency_check_gen_location_in_cert_circular_region[];
extern size_t g_sample_spdu_consistency_check_gen_location_in_cert_circular_region_size;
extern uint8_t g_sample_spdu_consistency_check_gen_location_out_of_cert_circular_region[];
extern size_t g_sample_spdu_consistency_check_gen_location_out_of_cert_circular_region_size;
extern uint8_t g_sample_spdu_consistency_check_gen_location_out_of_cert_identified_region[];
extern size_t g_sample_spdu_consistency_check_gen_location_out_of_cert_identified_region_size;


/*
 * 상위(CA)인증서 샘플 데이터
 */
extern uint8_t g_sample_rca_cert[];
extern size_t g_sample_rca_cert_size;
extern uint8_t g_sample_rca_cert_uncompressed_verification_key[];
extern uint8_t g_sample_rca_cert_compressed_verification_key[];
extern uint8_t g_sample_rca_cert_r_sig[];
extern uint8_t g_sample_rca_cert_s_sig[];
extern uint8_t g_sample_rca_cert_h[];
extern uint8_t g_sample_rca_cert_h8[];
extern uint8_t g_sample_rca_cert_h10[];
extern uint64_t g_sample_rca_valid_start;
extern uint64_t g_sample_rca_valid_end;
extern uint8_t g_sample_ica_cert[];
extern size_t g_sample_ica_cert_size;
extern uint8_t g_sample_ica_cert_uncompressed_verification_key[];
extern uint8_t g_sample_ica_cert_compressed_verification_key[];
extern uint8_t g_sample_ica_cert_r_sig[];
extern uint8_t g_sample_ica_cert_s_sig[];
extern uint8_t g_sample_ica_cert_issuer_h8[];
extern uint8_t g_sample_ica_cert_h[];
extern uint8_t g_sample_ica_cert_h8[];
extern uint8_t g_sample_ica_cert_h10[];
extern uint64_t g_sample_ica_valid_start;
extern uint64_t g_sample_ica_valid_end;
extern uint8_t g_sample_eca_cert[];
extern size_t g_sample_eca_cert_size;
extern uint8_t g_sample_eca_cert_uncompressed_verification_key[];
extern uint8_t g_sample_eca_cert_compressed_verification_key[];
extern uint8_t g_sample_eca_cert_r_sig[];
extern uint8_t g_sample_eca_cert_s_sig[];
extern uint8_t g_sample_eca_cert_issuer_h8[];
extern uint8_t g_sample_eca_cert_h[];
extern uint8_t g_sample_eca_cert_h8[];
extern uint8_t g_sample_eca_cert_h10[];
extern uint8_t g_sample_pca_cert[];
extern size_t g_sample_pca_cert_size;
extern uint8_t g_sample_pca_cert_uncompressed_verification_key[];
extern uint8_t g_sample_pca_cert_compressed_verification_key[];
extern uint8_t g_sample_pca_cert_r_sig[];
extern uint8_t g_sample_pca_cert_s_sig[];
extern uint8_t g_sample_pca_cert_issuer_h8[];
extern uint8_t g_sample_pca_cert_h[] ;
extern uint8_t g_sample_pca_cert_h8[];
extern uint8_t g_sample_pca_cert_h10[];
extern uint64_t g_sample_pca_valid_start;
extern uint64_t g_sample_pca_valid_end ;
extern uint8_t g_sample_ra_cert[];
extern size_t g_sample_ra_cert_size;
extern uint8_t g_sample_ra_cert_uncompressed_verification_key[];
extern uint8_t g_sample_ra_cert_compressed_verification_key[];
extern uint8_t g_sample_ra_cert_r_sig[];
extern uint8_t g_sample_ra_cert_s_sig[];
extern uint8_t g_sample_ra_cert_issuer_h8[];
extern uint8_t g_sample_ra_cert_h[];
extern uint8_t g_sample_ra_cert_h8[];
extern uint8_t g_sample_ra_cert_h10[];


/*
 * RSE 어플리케이션 인증서 샘플 데이터
 */
extern uint8_t g_sample_rse_0_cert[];
extern size_t g_sample_rse_0_cert_size;
extern uint8_t g_sample_rse_0_cert_reconstruct_value[];
extern uint8_t g_sample_rse_0_cert_issuer_h8[];
extern uint8_t g_sample_rse_0_cert_h[];
extern uint8_t g_sample_rse_0_cert_h8[];
extern uint8_t g_sample_rse_0_cert_h10[];
extern uint8_t g_sample_rse_0_cr_priv_key[];
extern uint8_t g_sample_rse_0_recon_priv[];
extern uint8_t g_sample_rse_0_priv_key[];
extern uint8_t g_sample_rse_0_cert_pub_key[];
extern uint64_t g_sample_rse_0_valid_time;
extern uint64_t g_sample_rse_0_valid_start;
extern uint64_t g_sample_rse_0_valid_end;
extern Dot2PSID g_sample_rse_0_psid;
extern Dot2Latitude g_sample_rse_0_valid_lat;
extern Dot2Longitude g_sample_rse_0_valid_lon;
extern Dot2Elevation g_sample_rse_0_valid_elev;
extern char g_sample_rse_0_key_cmhf_name[];
extern uint8_t g_sample_rse_0_cmhf[];
extern size_t g_sample_rse_0_cmhf_size;
extern uint8_t g_sample_rse_1_cert[];
extern size_t g_sample_rse_1_cert_size;
extern uint8_t g_sample_rse_1_cert_reconstruct_value[];
extern uint8_t g_sample_rse_1_cert_issuer_h8[];
extern uint8_t g_sample_rse_1_cert_h[];
extern uint8_t g_sample_rse_1_cert_h8[];
extern uint8_t g_sample_rse_1_cert_h10[];
extern uint8_t g_sample_rse_1_cr_priv_key[];
extern uint8_t g_sample_rse_1_recon_priv[];
extern uint8_t g_sample_rse_1_priv_key[];
extern uint8_t g_sample_rse_1_cert_pub_key[];
extern uint64_t g_sample_rse_1_valid_time;
extern uint64_t g_sample_rse_1_valid_start;
extern uint64_t g_sample_rse_1_valid_end;
extern Dot2PSID g_sample_rse_1_psid;
extern Dot2Latitude g_sample_rse_1_valid_lat;
extern Dot2Longitude g_sample_rse_1_valid_lon;
extern Dot2Elevation g_sample_rse_1_valid_elev;
extern char g_sample_rse_1_key_cmhf_name[];
extern uint8_t g_sample_rse_1_cmhf[];
extern size_t g_sample_rse_1_cmhf_size;
extern uint8_t g_sample_rse_2_cert[];
extern size_t g_sample_rse_2_cert_size;
extern uint8_t g_sample_rse_2_cert_reconstruct_value[];
extern uint8_t g_sample_rse_2_cert_issuer_h8[];
extern uint8_t g_sample_rse_2_cert_h[];
extern uint8_t g_sample_rse_2_cert_h8[];
extern uint8_t g_sample_rse_2_cert_h10[];
extern uint8_t g_sample_rse_2_cr_priv_key[];
extern uint8_t g_sample_rse_2_recon_priv[];
extern uint8_t g_sample_rse_2_priv_key[];
extern uint8_t g_sample_rse_2_cert_pub_key[];
extern uint64_t g_sample_rse_2_valid_time;
extern uint64_t g_sample_rse_2_valid_start;
extern uint64_t g_sample_rse_2_valid_end;
extern Dot2PSID g_sample_rse_2_psid;
extern Dot2Latitude g_sample_rse_2_valid_lat;
extern Dot2Longitude g_sample_rse_2_valid_lon;
extern Dot2Elevation g_sample_rse_2_valid_elev;
extern char g_sample_rse_2_key_cmhf_name[];
extern uint8_t g_sample_rse_2_cmhf[];
extern size_t g_sample_rse_2_cmhf_size;
extern uint8_t g_sample_rse_3_cert[];
extern size_t g_sample_rse_3_cert_size;
extern uint8_t g_sample_rse_3_cert_reconstruct_value[];
extern uint8_t g_sample_rse_3_cert_issuer_h8[];
extern uint8_t g_sample_rse_3_cert_h[];
extern uint8_t g_sample_rse_3_cert_h8[];
extern uint8_t g_sample_rse_3_cert_h10[];
extern uint8_t g_sample_rse_3_cr_priv_key[];
extern uint8_t g_sample_rse_3_recon_priv[];
extern uint8_t g_sample_rse_3_priv_key[];
extern uint8_t g_sample_rse_3_cert_pub_key[];
extern uint64_t g_sample_rse_3_valid_time;
extern uint64_t g_sample_rse_3_valid_start;
extern uint64_t g_sample_rse_3_valid_end;
extern Dot2PSID g_sample_rse_3_psid;
extern Dot2Latitude g_sample_rse_3_valid_lat;
extern Dot2Longitude g_sample_rse_3_valid_lon;
extern Dot2Elevation g_sample_rse_3_valid_elev;
extern char g_sample_rse_3_key_cmhf_name[];
extern uint8_t g_sample_rse_3_cmhf[];
extern size_t g_sample_rse_3_cmhf_size;
extern uint8_t g_sample_rse_4_cert[];
extern size_t g_sample_rse_4_cert_size;
extern uint8_t g_sample_rse_4_cert_reconstruct_value[];
extern uint8_t g_sample_rse_4_cert_issuer_h8[];
extern uint8_t g_sample_rse_4_cert_h[];
extern uint8_t g_sample_rse_4_cert_h8[];
extern uint8_t g_sample_rse_4_cert_h10[];
extern uint8_t g_sample_rse_4_cr_priv_key[];
extern uint8_t g_sample_rse_4_recon_priv[];
extern uint8_t g_sample_rse_4_priv_key[];
extern uint8_t g_sample_rse_4_cert_pub_key[];
extern uint64_t g_sample_rse_4_valid_time;
extern uint64_t g_sample_rse_4_valid_start;
extern uint64_t g_sample_rse_4_valid_end;
extern Dot2PSID g_sample_rse_4_psid;
extern Dot2Latitude g_sample_rse_4_valid_lat;
extern Dot2Longitude g_sample_rse_4_valid_lon;
extern Dot2Elevation g_sample_rse_4_valid_elev;
extern char g_sample_rse_4_key_cmhf_name[];
extern uint8_t g_sample_rse_4_cmhf[];
extern size_t g_sample_rse_4_cmhf_size;


/*
 * OBU 어플리케이션 인증서 샘플 데이터
 */
extern uint8_t g_sample_obu_expansion_key[];
extern uint8_t g_sample_obu_seed_priv[];
extern uint8_t g_sample_obu_10a_0_cert[];
extern size_t g_sample_obu_10a_0_cert_size;
extern uint8_t g_sample_obu_10a_0_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_0_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_0_cert_h[];
extern uint8_t g_sample_obu_10a_0_cert_h8[];
extern uint8_t g_sample_obu_10a_0_cert_h10[];
extern uint32_t g_sample_obu_10a_0_i;
extern uint32_t g_sample_obu_10a_0_j;
extern uint8_t g_sample_obu_10a_0_recon_priv[];
extern uint8_t g_sample_obu_10a_0_priv_key[];
extern uint8_t g_sample_obu_10a_0_cert_pub_key[];
extern uint64_t g_sample_obu_10a_0_valid_time;
extern uint64_t g_sample_obu_10a_0_valid_start;
extern uint64_t g_sample_obu_10a_0_valid_end;
extern Dot2PSID g_sample_obu_10a_0_psid_bsm;
extern Dot2PSID g_sample_obu_10a_0_psid_pvd;
extern Dot2Latitude g_sample_obu_10a_0_valid_lat;
extern Dot2Longitude g_sample_obu_10a_0_valid_lon;
extern Dot2Elevation g_sample_obu_10a_0_valid_elev;
extern char g_sample_obu_10a_0_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_0_cmhf[];
extern size_t g_sample_obu_10a_0_cmhf_size;
extern uint8_t g_sample_obu_10a_1_cert[];
extern size_t g_sample_obu_10a_1_cert_size;
extern uint8_t g_sample_obu_10a_1_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_1_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_1_cert_h[];
extern uint8_t g_sample_obu_10a_1_cert_h8[];
extern uint8_t g_sample_obu_10a_1_cert_h10[];
extern uint32_t g_sample_obu_10a_1_i;
extern uint32_t g_sample_obu_10a_1_j;
extern uint8_t g_sample_obu_10a_1_recon_priv[];
extern uint8_t g_sample_obu_10a_1_priv_key[];
extern uint8_t g_sample_obu_10a_1_cert_pub_key[];
extern uint64_t g_sample_obu_10a_1_valid_start;
extern uint64_t g_sample_obu_10a_1_valid_end;
extern char g_sample_obu_10a_1_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_1_cmhf[];
extern size_t g_sample_obu_10a_1_cmhf_size;
extern uint8_t g_sample_obu_10a_2_cert[];
extern size_t g_sample_obu_10a_2_cert_size;
extern uint8_t g_sample_obu_10a_2_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_2_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_2_cert_h[];
extern uint8_t g_sample_obu_10a_2_cert_h8[];
extern uint8_t g_sample_obu_10a_2_cert_h10[];
extern uint32_t g_sample_obu_10a_2_i;
extern uint32_t g_sample_obu_10a_2_j;
extern uint8_t g_sample_obu_10a_2_recon_priv[];
extern uint8_t g_sample_obu_10a_2_priv_key[];
extern uint8_t g_sample_obu_10a_2_cert_pub_key[];
extern uint64_t g_sample_obu_10a_2_valid_start;
extern uint64_t g_sample_obu_10a_2_valid_end;
extern char g_sample_obu_10a_2_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_2_cmhf[];
extern size_t g_sample_obu_10a_2_cmhf_size;
extern uint8_t g_sample_obu_10a_3_cert[];
extern size_t g_sample_obu_10a_3_cert_size;
extern uint8_t g_sample_obu_10a_3_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_3_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_3_cert_h[];
extern uint8_t g_sample_obu_10a_3_cert_h8[];
extern uint8_t g_sample_obu_10a_3_cert_h10[];
extern uint32_t g_sample_obu_10a_3_i;
extern uint32_t g_sample_obu_10a_3_j;
extern uint8_t g_sample_obu_10a_3_recon_priv[];
extern uint8_t g_sample_obu_10a_3_priv_key[];
extern uint8_t g_sample_obu_10a_3_cert_pub_key[];
extern uint64_t g_sample_obu_10a_3_valid_start;
extern uint64_t g_sample_obu_10a_3_valid_end;
extern char g_sample_obu_10a_3_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_3_cmhf[];
extern size_t g_sample_obu_10a_3_cmhf_size;
extern uint8_t g_sample_obu_10a_4_cert[];
extern size_t g_sample_obu_10a_4_cert_size;
extern uint8_t g_sample_obu_10a_4_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_4_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_4_cert_h[];
extern uint8_t g_sample_obu_10a_4_cert_h8[];
extern uint8_t g_sample_obu_10a_4_cert_h10[];
extern uint32_t g_sample_obu_10a_4_i;
extern uint32_t g_sample_obu_10a_4_j;
extern uint8_t g_sample_obu_10a_4_recon_priv[];
extern uint8_t g_sample_obu_10a_4_priv_key[];
extern uint8_t g_sample_obu_10a_4_cert_pub_key[];
extern uint64_t g_sample_obu_10a_4_valid_start;
extern uint64_t g_sample_obu_10a_4_valid_end;
extern char g_sample_obu_10a_4_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_4_cmhf[];
extern size_t g_sample_obu_10a_4_cmhf_size;
extern uint8_t g_sample_obu_10a_5_cert[];
extern size_t g_sample_obu_10a_5_cert_size;
extern uint8_t g_sample_obu_10a_5_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_5_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_5_cert_h[];
extern uint8_t g_sample_obu_10a_5_cert_h8[];
extern uint8_t g_sample_obu_10a_5_cert_h10[];
extern uint32_t g_sample_obu_10a_5_i;
extern uint32_t g_sample_obu_10a_5_j;
extern uint8_t g_sample_obu_10a_5_recon_priv[];
extern uint8_t g_sample_obu_10a_5_priv_key[];
extern uint8_t g_sample_obu_10a_5_cert_pub_key[];
extern uint64_t g_sample_obu_10a_5_valid_start;
extern uint64_t g_sample_obu_10a_5_valid_end;
extern char g_sample_obu_10a_5_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_5_cmhf[];
extern size_t g_sample_obu_10a_5_cmhf_size;
extern uint8_t g_sample_obu_10a_6_cert[];
extern size_t g_sample_obu_10a_6_cert_size;
extern uint8_t g_sample_obu_10a_6_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_6_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_6_cert_h[];
extern uint8_t g_sample_obu_10a_6_cert_h8[];
extern uint8_t g_sample_obu_10a_6_cert_h10[];
extern uint32_t g_sample_obu_10a_6_i;
extern uint32_t g_sample_obu_10a_6_j;
extern uint8_t g_sample_obu_10a_6_recon_priv[];
extern uint8_t g_sample_obu_10a_6_priv_key[];
extern uint8_t g_sample_obu_10a_6_cert_pub_key[];
extern uint64_t g_sample_obu_10a_6_valid_start;
extern uint64_t g_sample_obu_10a_6_valid_end;
extern char g_sample_obu_10a_6_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_6_cmhf[];
extern size_t g_sample_obu_10a_6_cmhf_size;
extern uint8_t g_sample_obu_10a_7_cert[];
extern size_t g_sample_obu_10a_7_cert_size;
extern uint8_t g_sample_obu_10a_7_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_7_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_7_cert_h[];
extern uint8_t g_sample_obu_10a_7_cert_h8[];
extern uint8_t g_sample_obu_10a_7_cert_h10[];
extern uint32_t g_sample_obu_10a_7_i;
extern uint32_t g_sample_obu_10a_7_j;
extern uint8_t g_sample_obu_10a_7_recon_priv[];
extern uint8_t g_sample_obu_10a_7_priv_key[];
extern uint8_t g_sample_obu_10a_7_cert_pub_key[];
extern uint64_t g_sample_obu_10a_7_valid_start;
extern uint64_t g_sample_obu_10a_7_valid_end;
extern char g_sample_obu_10a_7_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_7_cmhf[];
extern size_t g_sample_obu_10a_7_cmhf_size;
extern uint8_t g_sample_obu_10a_8_cert[];
extern size_t g_sample_obu_10a_8_cert_size;
extern uint8_t g_sample_obu_10a_8_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_8_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_8_cert_h[];
extern uint8_t g_sample_obu_10a_8_cert_h8[];
extern uint8_t g_sample_obu_10a_8_cert_h10[];
extern uint32_t g_sample_obu_10a_8_i;
extern uint32_t g_sample_obu_10a_8_j;
extern uint8_t g_sample_obu_10a_8_recon_priv[];
extern uint8_t g_sample_obu_10a_8_priv_key[];
extern uint8_t g_sample_obu_10a_8_cert_pub_key[];
extern uint64_t g_sample_obu_10a_8_valid_start;
extern uint64_t g_sample_obu_10a_8_valid_end;
extern char g_sample_obu_10a_8_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_8_cmhf[];
extern size_t g_sample_obu_10a_8_cmhf_size;
extern uint8_t g_sample_obu_10a_9_cert[];
extern size_t g_sample_obu_10a_9_cert_size;
extern uint8_t g_sample_obu_10a_9_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_9_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_9_cert_h[];
extern uint8_t g_sample_obu_10a_9_cert_h8[];
extern uint8_t g_sample_obu_10a_9_cert_h10[];
extern uint32_t g_sample_obu_10a_9_i;
extern uint32_t g_sample_obu_10a_9_j;
extern uint8_t g_sample_obu_10a_9_recon_priv[];
extern uint8_t g_sample_obu_10a_9_priv_key[];
extern uint8_t g_sample_obu_10a_9_cert_pub_key[];
extern uint64_t g_sample_obu_10a_9_valid_start;
extern uint64_t g_sample_obu_10a_9_valid_end;
extern char g_sample_obu_10a_9_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_9_cmhf[];
extern size_t g_sample_obu_10a_9_cmhf_size;
extern uint8_t g_sample_obu_10a_a_cert[];
extern size_t g_sample_obu_10a_a_cert_size;
extern uint8_t g_sample_obu_10a_a_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_a_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_a_cert_h[];
extern uint8_t g_sample_obu_10a_a_cert_h8[];
extern uint8_t g_sample_obu_10a_a_cert_h10[];
extern uint32_t g_sample_obu_10a_a_i;
extern uint32_t g_sample_obu_10a_a_j;
extern uint8_t g_sample_obu_10a_a_recon_priv[];
extern uint8_t g_sample_obu_10a_a_priv_key[];
extern uint8_t g_sample_obu_10a_a_cert_pub_key[];
extern uint64_t g_sample_obu_10a_a_valid_start;
extern uint64_t g_sample_obu_10a_a_valid_end;
extern char g_sample_obu_10a_a_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_a_cmhf[];
extern size_t g_sample_obu_10a_a_cmhf_size;
extern uint8_t g_sample_obu_10a_b_cert[];
extern size_t g_sample_obu_10a_b_cert_size;
extern uint8_t g_sample_obu_10a_b_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_b_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_b_cert_h[];
extern uint8_t g_sample_obu_10a_b_cert_h8[];
extern uint8_t g_sample_obu_10a_b_cert_h10[];
extern uint32_t g_sample_obu_10a_b_i;
extern uint32_t g_sample_obu_10a_b_j;
extern uint8_t g_sample_obu_10a_b_recon_priv[];
extern uint8_t g_sample_obu_10a_b_priv_key[];
extern uint8_t g_sample_obu_10a_b_cert_pub_key[];
extern uint64_t g_sample_obu_10a_b_valid_start;
extern uint64_t g_sample_obu_10a_b_valid_end;
extern char g_sample_obu_10a_b_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_b_cmhf[];
extern size_t g_sample_obu_10a_b_cmhf_size;
extern uint8_t g_sample_obu_10a_c_cert[];
extern size_t g_sample_obu_10a_c_cert_size;
extern uint8_t g_sample_obu_10a_c_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_c_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_c_cert_h[];
extern uint8_t g_sample_obu_10a_c_cert_h8[];
extern uint8_t g_sample_obu_10a_c_cert_h10[];
extern uint32_t g_sample_obu_10a_c_i;
extern uint32_t g_sample_obu_10a_c_j;
extern uint8_t g_sample_obu_10a_c_recon_priv[];
extern uint8_t g_sample_obu_10a_c_priv_key[];
extern uint8_t g_sample_obu_10a_c_cert_pub_key[];
extern uint64_t g_sample_obu_10a_c_valid_start;
extern uint64_t g_sample_obu_10a_c_valid_end;
extern char g_sample_obu_10a_c_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_c_cmhf[];
extern size_t g_sample_obu_10a_c_cmhf_size;
extern uint8_t g_sample_obu_10a_d_cert[];
extern size_t g_sample_obu_10a_d_cert_size;
extern uint8_t g_sample_obu_10a_d_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_d_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_d_cert_h[];
extern uint8_t g_sample_obu_10a_d_cert_h8[];
extern uint8_t g_sample_obu_10a_d_cert_h10[];
extern uint32_t g_sample_obu_10a_d_i;
extern uint32_t g_sample_obu_10a_d_j;
extern uint8_t g_sample_obu_10a_d_recon_priv[];
extern uint8_t g_sample_obu_10a_d_priv_key[];
extern uint8_t g_sample_obu_10a_d_cert_pub_key[];
extern uint64_t g_sample_obu_10a_d_valid_start;
extern uint64_t g_sample_obu_10a_d_valid_end;
extern char g_sample_obu_10a_d_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_d_cmhf[];
extern size_t g_sample_obu_10a_d_cmhf_size;
extern uint8_t g_sample_obu_10a_e_cert[];
extern size_t g_sample_obu_10a_e_cert_size;
extern uint8_t g_sample_obu_10a_e_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_e_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_e_cert_h[];
extern uint8_t g_sample_obu_10a_e_cert_h8[];
extern uint8_t g_sample_obu_10a_e_cert_h10[];
extern uint32_t g_sample_obu_10a_e_i;
extern uint32_t g_sample_obu_10a_e_j;
extern uint8_t g_sample_obu_10a_e_recon_priv[];
extern uint8_t g_sample_obu_10a_e_priv_key[];
extern uint8_t g_sample_obu_10a_e_cert_pub_key[];
extern uint64_t g_sample_obu_10a_e_valid_start;
extern uint64_t g_sample_obu_10a_e_valid_end;
extern char g_sample_obu_10a_e_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_e_cmhf[];
extern size_t g_sample_obu_10a_e_cmhf_size;
extern uint8_t g_sample_obu_10a_f_cert[];
extern size_t g_sample_obu_10a_f_cert_size;
extern uint8_t g_sample_obu_10a_f_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_f_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_f_cert_h[];
extern uint8_t g_sample_obu_10a_f_cert_h8[];
extern uint8_t g_sample_obu_10a_f_cert_h10[];
extern uint32_t g_sample_obu_10a_f_i;
extern uint32_t g_sample_obu_10a_f_j;
extern uint8_t g_sample_obu_10a_f_recon_priv[];
extern uint8_t g_sample_obu_10a_f_priv_key[];
extern uint8_t g_sample_obu_10a_f_cert_pub_key[];
extern uint64_t g_sample_obu_10a_f_valid_start;
extern uint64_t g_sample_obu_10a_f_valid_end;
extern char g_sample_obu_10a_f_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_f_cmhf[];
extern size_t g_sample_obu_10a_f_cmhf_size;
extern uint8_t g_sample_obu_10a_10_cert[];
extern size_t g_sample_obu_10a_10_cert_size;
extern uint8_t g_sample_obu_10a_10_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_10_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_10_cert_h[];
extern uint8_t g_sample_obu_10a_10_cert_h8[];
extern uint8_t g_sample_obu_10a_10_cert_h10[];
extern uint32_t g_sample_obu_10a_10_i;
extern uint32_t g_sample_obu_10a_10_j;
extern uint8_t g_sample_obu_10a_10_recon_priv[];
extern uint8_t g_sample_obu_10a_10_priv_key[];
extern uint8_t g_sample_obu_10a_10_cert_pub_key[];
extern uint64_t g_sample_obu_10a_10_valid_start;
extern uint64_t g_sample_obu_10a_10_valid_end;
extern char g_sample_obu_10a_10_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_10_cmhf[];
extern size_t g_sample_obu_10a_10_cmhf_size;
extern uint8_t g_sample_obu_10a_11_cert[];
extern size_t g_sample_obu_10a_11_cert_size;
extern uint8_t g_sample_obu_10a_11_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_11_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_11_cert_h[];
extern uint8_t g_sample_obu_10a_11_cert_h8[];
extern uint8_t g_sample_obu_10a_11_cert_h10[];;
extern uint32_t g_sample_obu_10a_11_i;
extern uint32_t g_sample_obu_10a_11_j;
extern uint8_t g_sample_obu_10a_11_recon_priv[];
extern uint8_t g_sample_obu_10a_11_priv_key[];
extern uint8_t g_sample_obu_10a_11_cert_pub_key[];
extern uint64_t g_sample_obu_10a_11_valid_start;
extern uint64_t g_sample_obu_10a_11_valid_end;
extern char g_sample_obu_10a_11_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_11_cmhf[];
extern size_t g_sample_obu_10a_11_cmhf_size;
extern uint8_t g_sample_obu_10a_12_cert[];
extern size_t g_sample_obu_10a_12_cert_size;
extern uint8_t g_sample_obu_10a_12_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_12_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_12_cert_h[];
extern uint8_t g_sample_obu_10a_12_cert_h8[];
extern uint8_t g_sample_obu_10a_12_cert_h10[];;
extern uint32_t g_sample_obu_10a_12_i;
extern uint32_t g_sample_obu_10a_12_j;
extern uint8_t g_sample_obu_10a_12_recon_priv[];
extern uint8_t g_sample_obu_10a_12_priv_key[];
extern uint8_t g_sample_obu_10a_12_cert_pub_key[];
extern uint64_t g_sample_obu_10a_12_valid_start;
extern uint64_t g_sample_obu_10a_12_valid_end;
extern char g_sample_obu_10a_12_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_12_cmhf[];
extern size_t g_sample_obu_10a_12_cmhf_size;
extern uint8_t g_sample_obu_10a_13_cert[];
extern size_t g_sample_obu_10a_13_cert_size;
extern uint8_t g_sample_obu_10a_13_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10a_13_cert_issuer_h8[];
extern uint8_t g_sample_obu_10a_13_cert_h[];
extern uint8_t g_sample_obu_10a_13_cert_h8[];
extern uint8_t g_sample_obu_10a_13_cert_h10[];;
extern uint32_t g_sample_obu_10a_13_i;
extern uint32_t g_sample_obu_10a_13_j;
extern uint8_t g_sample_obu_10a_13_recon_priv[];
extern uint8_t g_sample_obu_10a_13_priv_key[];
extern uint8_t g_sample_obu_10a_13_cert_pub_key[];
extern uint64_t g_sample_obu_10a_13_valid_start;
extern uint64_t g_sample_obu_10a_13_valid_end;
extern char g_sample_obu_10a_13_key_cmhf_name[];
extern uint8_t g_sample_obu_10a_13_cmhf[];
extern size_t g_sample_obu_10a_13_cmhf_size;
extern uint8_t g_sample_obu_10b_0_cert[];
extern size_t g_sample_obu_10b_0_cert_size;
extern uint8_t g_sample_obu_10b_0_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10b_0_cert_issuer_h8[];
extern uint8_t g_sample_obu_10b_0_cert_h[];
extern uint8_t g_sample_obu_10b_0_cert_h8[];
extern uint8_t g_sample_obu_10b_0_cert_h10[];;
extern uint32_t g_sample_obu_10b_0_i;
extern uint32_t g_sample_obu_10b_0_j;
extern uint8_t g_sample_obu_10b_0_recon_priv[];
extern uint8_t g_sample_obu_10b_0_priv_key[];
extern uint8_t g_sample_obu_10b_0_cert_pub_key[];
extern uint64_t g_sample_obu_10b_0_valid_time;
extern uint64_t g_sample_obu_10b_0_valid_start;
extern uint64_t g_sample_obu_10b_0_valid_end;
extern Dot2PSID g_sample_obu_10b_0_psid_bsm;
extern Dot2PSID g_sample_obu_10b_0_psid_pvd;
extern Dot2Latitude g_sample_obu_10b_0_valid_lat;
extern Dot2Longitude g_sample_obu_10b_0_valid_lon;
extern Dot2Elevation g_sample_obu_10b_0_valid_elev;
extern char g_sample_obu_10b_0_key_cmhf_name[];
extern uint8_t g_sample_obu_10b_0_cmhf[];
extern size_t g_sample_obu_10b_0_cmhf_size;
extern uint8_t g_sample_obu_10c_0_cert[];
extern size_t g_sample_obu_10c_0_cert_size;
extern uint8_t g_sample_obu_10c_0_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10c_0_cert_issuer_h8[];
extern uint8_t g_sample_obu_10c_0_cert_h[];
extern uint8_t g_sample_obu_10c_0_cert_h8[];
extern uint8_t g_sample_obu_10c_0_cert_h10[];
extern uint32_t g_sample_obu_10c_0_i;
extern uint32_t g_sample_obu_10c_0_j;
extern uint8_t g_sample_obu_10c_0_recon_priv[];
extern uint8_t g_sample_obu_10c_0_priv_key[];
extern uint8_t g_sample_obu_10c_0_cert_pub_key[];
extern uint64_t g_sample_obu_10c_0_valid_time;
extern uint64_t g_sample_obu_10c_0_valid_start;
extern uint64_t g_sample_obu_10c_0_valid_end;
extern Dot2PSID g_sample_obu_10c_0_psid_bsm;
extern Dot2PSID g_sample_obu_10c_0_psid_pvd;
extern Dot2Latitude g_sample_obu_10c_0_valid_lat;
extern Dot2Longitude g_sample_obu_10c_0_valid_lon;
extern Dot2Elevation g_sample_obu_10c_0_valid_elev;
extern char g_sample_obu_10c_0_key_cmhf_name[];
extern uint8_t g_sample_obu_10c_0_cmhf[];
extern size_t g_sample_obu_10c_0_cmhf_size;
extern uint8_t g_sample_obu_10d_0_cert[];
extern size_t g_sample_obu_10d_0_cert_size;
extern uint8_t g_sample_obu_10d_0_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10d_0_cert_issuer_h8[];
extern uint8_t g_sample_obu_10d_0_cert_h[];
extern uint8_t g_sample_obu_10d_0_cert_h8[];
extern uint8_t g_sample_obu_10d_0_cert_h10[];
extern uint32_t g_sample_obu_10d_0_i;
extern uint32_t g_sample_obu_10d_0_j;
extern uint8_t g_sample_obu_10d_0_recon_priv[];
extern uint8_t g_sample_obu_10d_0_priv_key[];
extern uint8_t g_sample_obu_10d_0_cert_pub_key[];
extern uint64_t g_sample_obu_10d_0_valid_time;
extern uint64_t g_sample_obu_10d_0_valid_start;
extern uint64_t g_sample_obu_10d_0_valid_end;
extern Dot2PSID g_sample_obu_10d_0_psid_bsm;
extern Dot2PSID g_sample_obu_10d_0_psid_pvd;
extern Dot2Latitude g_sample_obu_10d_0_valid_lat;
extern Dot2Longitude g_sample_obu_10d_0_valid_lon;
extern Dot2Elevation g_sample_obu_10d_0_valid_elev;
extern char g_sample_obu_10d_0_key_cmhf_name[];
extern uint8_t g_sample_obu_10d_0_cmhf[];
extern size_t g_sample_obu_10d_0_cmhf_size;
extern uint8_t g_sample_obu_10e_0_cert[];
extern size_t g_sample_obu_10e_0_cert_size;
extern uint8_t g_sample_obu_10e_0_cert_reconstruct_value[];
extern uint8_t g_sample_obu_10e_0_cert_issuer_h8[];
extern uint8_t g_sample_obu_10e_0_cert_h[];
extern uint8_t g_sample_obu_10e_0_cert_h8[];
extern uint8_t g_sample_obu_10e_0_cert_h10[];
extern uint32_t g_sample_obu_10e_0_i;
extern uint32_t g_sample_obu_10e_0_j;
extern uint8_t g_sample_obu_10e_0_recon_priv[];
extern uint8_t g_sample_obu_10e_0_priv_key[];
extern uint8_t g_sample_obu_10e_0_cert_pub_key[];
extern uint64_t g_sample_obu_10e_0_valid_time;
extern uint64_t g_sample_obu_10e_0_valid_start;
extern uint64_t g_sample_obu_10e_0_valid_end;
extern Dot2PSID g_sample_obu_10e_0_psid_bsm;
extern Dot2PSID g_sample_obu_10e_0_psid_pvd;
extern Dot2Latitude g_sample_obu_10e_0_valid_lat;
extern Dot2Longitude g_sample_obu_10e_0_valid_lon;
extern Dot2Elevation g_sample_obu_10e_0_valid_elev;
extern char g_sample_obu_10e_0_key_cmhf_name[];
extern uint8_t g_sample_obu_10e_0_cmhf[];
extern size_t g_sample_obu_10e_0_cmhf_size;


#ifdef _SUPPORT_SCMS_

/*
 * LCM 등록인증서 발급 테스트벡터
 */
extern const char *g_tv_ecreq_1;
extern size_t g_tv_ecreq_size_1;
extern const char *g_tv_ecreq_init_priv_key_1;
extern const char *g_tv_ecreq_init_pub_key_1;
extern const char *g_tv_ecreq_h8_1;
extern const char *g_tv_ecresp_1;
extern size_t g_tv_ecresp_size_1;
extern const char *g_tv_ecresp_enroll_cert_1;
extern size_t g_tv_ecresp_enroll_cert_size_1;
extern const char *g_tv_ecresp_recon_priv_1;
extern const char *g_tv_ecresp_eca_cert_1;
extern size_t g_tv_ecresp_eca_cert_size_1;
extern const char *g_tv_ecresp_ra_cert_1;
extern size_t g_tv_ecresp_ra_cert_size_1;
extern const char *g_tv_ecresp_rca_cert_1;
extern size_t g_tv_ecresp_rca_cert_size_1;
extern const char *g_tv_ecresp_lccf_1;
extern size_t g_tv_ecresp_lccf_size_1;
extern const char *g_tv_ecresp_ica_cert_1;
extern size_t g_tv_ecresp_ica_cert_size_1;
extern const char *g_tv_ecresp_pca_cert_1;
extern size_t g_tv_ecresp_pca_cert_size_1;
extern const char *g_tv_ecresp_enroll_priv_key_1;
extern const char *g_tv_ecresp_enroll_pub_key_1;
extern const char *g_tv_ecreq_2;
extern size_t g_tv_ecreq_size_2;
extern const char *g_tv_ecreq_init_priv_key_2;
extern const char *g_tv_ecreq_init_pub_key_2;
extern const char *g_tv_ecreq_h8_2;
extern const char *g_tv_ecresp_2;
extern size_t g_tv_ecresp_size_2;
extern const char *g_tv_ecresp_enroll_cert_2;
extern size_t g_tv_ecresp_enroll_cert_size_2;
extern const char *g_tv_ecresp_recon_priv_2;
extern const char *g_tv_ecresp_eca_cert_2;
extern size_t g_tv_ecresp_eca_cert_size_2;
extern const char *g_tv_ecresp_ra_cert_2;
extern size_t g_tv_ecresp_ra_cert_size_2;
extern const char *g_tv_ecresp_rca_cert_2;
extern size_t g_tv_ecresp_rca_cert_size_2;
extern const char *g_tv_ecresp_lccf_2;
extern size_t g_tv_ecresp_lccf_size_2;
extern const char *g_tv_ecresp_ica_cert_2;
extern size_t g_tv_ecresp_ica_cert_size_2;
extern const char *g_tv_ecresp_pca_cert_2;
extern size_t g_tv_ecresp_pca_cert_size_2;
extern const char *g_tv_ecresp_enroll_priv_key_2;
extern const char *g_tv_ecresp_enroll_pub_key_2;
extern const char *g_tv_ecreq_3;
extern size_t g_tv_ecreq_size_3;
extern const char *g_tv_ecreq_init_priv_key_3;
extern const char *g_tv_ecreq_init_pub_key_3;
extern const char *g_tv_ecreq_h8_3;
extern const char *g_tv_ecresp_3;
extern size_t g_tv_ecresp_size_3;
extern const char *g_tv_ecresp_enroll_cert_3;
extern size_t g_tv_ecresp_enroll_cert_size_3;
extern const char *g_tv_ecresp_recon_priv_3;
extern const char *g_tv_ecresp_eca_cert_3;
extern size_t g_tv_ecresp_eca_cert_size_3;
extern const char *g_tv_ecresp_ra_cert_3;
extern size_t g_tv_ecresp_ra_cert_size_3;
extern const char *g_tv_ecresp_rca_cert_3;
extern size_t g_tv_ecresp_rca_cert_size_3;
extern const char *g_tv_ecresp_lccf_3;
extern size_t g_tv_ecresp_lccf_size_3;
extern const char *g_tv_ecresp_ica_cert_3;
extern size_t g_tv_ecresp_ica_cert_size_3;
extern const char *g_tv_ecresp_pca_cert_3;
extern size_t g_tv_ecresp_pca_cert_size_3;
extern const char *g_tv_ecresp_enroll_priv_key_3;
extern const char *g_tv_ecresp_enroll_pub_key_3;

#endif


/*
 * test-vector-lcm-bluetech.cc
 */
struct Dot2TestPseudonymIdCertDown {
  const char *cert_filename;
  const char *cert;
  size_t cert_size;
  const char *priv_key_filename;
  const char *priv_key;
  const char *recon_priv_filename;
  const char *recon_priv;
};
struct Dot2TestCertDownResponse {
  const char *resp;
  size_t resp_size;
};
extern const char *g_tv_bluetech_ra;
extern size_t g_tv_bluetech_ra_size;
extern const char *g_tv_bluetech_ica;
extern size_t g_tv_bluetech_ica_size;
extern const char *g_tv_bluetech_pca;
extern size_t g_tv_bluetech_pca_size;
extern const char *g_tv_bluetech_eca;
extern size_t g_tv_bluetech_eca_size;
extern const char *g_tv_bluetech_rca;
extern size_t g_tv_bluetech_rca_size;
extern const char *g_tv_bluetech_crlg;
extern size_t g_tv_bluetech_crlg_size;
extern const char *g_tv_bluetech_lpf_req_url;
extern const char *g_tv_bluetech_lccf_req_url;
extern const char *g_tv_bluetech_crl_req_url;
extern const char *g_tv_bluetech_app_cert_req_url;
extern const char *g_tv_bluetech_pseudonym_cert_req_url;
extern const char *g_tv_bluetech_id_cert_req_url;
extern const char *g_tv_bluetech_rca_tls_cert_path;
extern const char *g_tv_bluetech_zip_file_path;
extern const char *g_tv_bluetech_ec_req;
extern size_t g_tv_bluetech_ec_req_size;
extern Dot2Time32 g_tv_bluetech_ec_req_current_time;
extern Dot2Time32 g_tv_bluetech_ec_req_valid_start;
extern Dot2CertDurationType g_tv_bluetech_ec_req_duration_type;
extern uint16_t g_tv_bluetech_ec_req_duration;
extern Dot2IdentifiedRegionNum g_tv_bluetech_ec_req_region_num;
extern Dot2CountryCode g_tv_bluetech_ec_req_region[];
extern Dot2CertPermissionNum g_tv_bluetech_ec_req_perms_num;
extern Dot2PSID g_tv_bluetech_ec_req_perms[];
extern const char *g_tv_bluetech_ec_req_init_priv_key;
extern const char *g_tv_bluetech_ec_resp_recon_priv;
extern const char *g_tv_bluetech_ec_resp_enrol_cert;
extern size_t g_tv_bluetech_ec_resp_enrol_cert_size;
extern const char *g_tv_bluetech_ec_resp_priv_key;
extern const char *g_tv_bluetech_ec_resp_lccf;
extern size_t g_tv_bluetech_ec_resp_lccf_size;
extern const char *g_tv_bluetech_ec_resp_enrol_cmhf_name;
extern const char *g_tv_bluetech_ec_resp_enrol_cmhf;
extern size_t g_tv_bluetech_ec_resp_enrol_cmhf_size;
extern const char *g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv;
extern const char *g_tv_bluetech_app_cert_prov_req_initial_verify_key_pub;
extern const char *g_tv_bluetech_app_cert_prov_req_encryption_key_priv;
extern const char *g_tv_bluetech_app_cert_prov_req_encryption_key_pub;
extern const char *g_tv_bluetech_app_cert_prov_req;
extern size_t g_tv_bluetech_app_cert_prov_req_size;
extern const char *g_tv_bluetech_app_cert_prov_req_h8;
extern const char *g_tv_bluetech_app_cert_prov_resp;
extern size_t g_tv_bluetech_app_cert_prov_resp_size;
extern unsigned int g_tv_bluetech_app_cert_prov_resp_cert_dl_time;
extern const char *g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
extern const char *g_tv_bluetech_app_cert_down_req_filename;
extern const char *g_tv_bluetech_app_cert_down_zipfile;
extern size_t g_tv_bluetech_app_cert_down_zipfile_size;
extern struct Dot2TestCertDownResponse g_tv_bluetech_app_cert_down_resp;
extern const char *g_tv_bluetech_app_cert_down_cmhf_name;
extern const char *g_tv_bluetech_app_cert_down_cmhf;
extern size_t g_tv_bluetech_app_cert_down_cmhf_size;
extern const char *g_tv_bluetech_app_cert_down_dir_name;
extern const char *g_tv_bluetech_app_cert_down_cert_filename;
extern const char *g_tv_bluetech_app_cert_down_cert;
extern size_t g_tv_bluetech_app_cert_down_cert_size;
extern const char *g_tv_bluetech_app_cert_down_priv_key_filename;
extern const char *g_tv_bluetech_app_cert_down_priv_key;
extern const char *g_tv_bluetech_app_cert_down_recon_priv_filename;
extern const char *g_tv_bluetech_app_cert_down_recon_priv;
extern const char *g_tv_bluetech_lccf_filename;
extern const char *g_tv_bluetech_lccf;
extern size_t g_tv_bluetech_lccf_size;
extern unsigned int g_tv_bluetech_lccf_resp_hdr_num;
extern const char *g_tv_bluetech_lccf_resp_hdr[];
extern unsigned int g_tv_bluetech_lccf_resp_hdr_not_modified_num;
extern const char *g_tv_bluetech_lccf_resp_hdr_not_modified;
extern const char *g_tv_bluetech_lccf_resp_hdr_no_filename;
extern const char *g_tv_bluetech_lccf_resp_hdr_empty_filename;
extern const char *g_tv_bluetech_lpf_filename;
extern const char *g_tv_bluetech_lpf;
extern size_t g_tv_bluetech_lpf_size;
extern unsigned int g_tv_bluetech_lpf_resp_hdr_num;
extern const char *g_tv_bluetech_lpf_resp_hdr[];
extern unsigned int g_tv_bluetech_lpf_resp_hdr_not_modified_num;
extern const char *g_tv_bluetech_lpf_resp_hdr_not_modified;
extern const char *g_tv_bluetech_lpf_resp_hdr_no_filename;
extern const char *g_tv_bluetech_lpf_resp_hdr_empty_filename;
extern const char *g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv;
extern const char *g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_pub;
extern const char *g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp;
extern const char *g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv;
extern const char *g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_pub;
extern const char *g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp;
extern const char *g_tv_bluetech_pseudonym_cert_prov_req_h8;
extern const char *g_tv_bluetech_pseudonym_cert_prov_resp;
extern size_t g_tv_bluetech_pseudonym_cert_prov_resp_size;
extern unsigned int g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
extern const char *g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
extern const char *g_tv_bluetech_pseudonym_cert_down_req_filename_1A9;
extern unsigned int g_tv_bluetech_pseudonym_cert_down_req_1A9_i_period;
extern const char *g_tv_bluetech_pseudonym_cert_down_zipfile_1A9;
extern size_t g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9;
extern struct Dot2TestCertDownResponse g_tv_bluetech_pseudonym_cert_down_resp_1A9[];
extern const char *g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9;
extern const char *g_tv_bluetech_pseudonym_cert_down_cmhf_1A9;
extern size_t g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9;
extern const char *g_tv_bluetech_pseudonym_cert_down_dir_name_1A9;
extern struct Dot2TestPseudonymIdCertDown g_tv_bluetech_pseudonym_cert_down_1A9[];
extern const char *g_tv_bluetech_pseudonym_cert_down_req_filename_1AA;
extern unsigned int g_tv_bluetech_pseudonym_cert_down_req_1AA_i_period;
extern const char *g_tv_bluetech_pseudonym_cert_down_zipfile_1AA;
extern size_t g_tv_bluetech_pseudonym_cert_down_zipfile_size_1AA;
extern struct Dot2TestCertDownResponse g_tv_bluetech_pseudonym_cert_down_resp_1AA[];
extern const char *g_tv_bluetech_pseudonym_cert_down_cmhf_name_1AA;
extern const char *g_tv_bluetech_pseudonym_cert_down_cmhf_1AA;
extern size_t g_tv_bluetech_pseudonym_cert_down_cmhf_size_1AA;
extern const char *g_tv_bluetech_pseudonym_cert_down_dir_name_1AA;
extern struct Dot2TestPseudonymIdCertDown g_tv_bluetech_pseudonym_cert_down_1AA[];
extern const char *g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
extern const char *g_tv_bluetech_pseudonym_cert_down_info_req_filename;
extern const char *g_tv_bluetech_pseudonym_cert_down_info_resp;
extern size_t g_tv_bluetech_pseudonym_cert_down_info_resp_size;
extern unsigned int g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
extern const char *g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv;
extern const char *g_tv_bluetech_id_cert_prov_req_initial_verify_key_pub;
extern const char *g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp;
extern const char *g_tv_bluetech_id_cert_prov_req_encryption_key_priv;
extern const char *g_tv_bluetech_id_cert_prov_req_encryption_key_pub;
extern const char *g_tv_bluetech_id_cert_prov_req_encryption_key_exp;
extern const char *g_tv_bluetech_id_cert_prov_req_h8;
extern const char *g_tv_bluetech_id_cert_prov_resp;
extern size_t g_tv_bluetech_id_cert_prov_resp_size;
extern unsigned int g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
extern const char *g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
extern unsigned int g_tv_bluetech_id_cert_down_req_0_i_period;
extern const char *g_tv_bluetech_id_cert_down_req_filename_0;
extern const char *g_tv_bluetech_id_cert_down_zipfile_0;
extern size_t g_tv_bluetech_id_cert_down_zipfile_size_0;
extern const char *g_tv_bluetech_id_cert_down_resp_0;
extern size_t g_tv_bluetech_id_cert_down_resp_size_0;
extern const char *g_tv_bluetech_id_cert_down_cmhf_name_0;
extern const char *g_tv_bluetech_id_cert_down_cmhf_0;
extern size_t g_tv_bluetech_id_cert_down_cmhf_size_0;
extern const char *g_tv_bluetech_id_cert_down_dir_name_0;
extern struct Dot2TestPseudonymIdCertDown g_tv_bluetech_id_cert_down_0;
extern unsigned int g_tv_bluetech_id_cert_down_req_1_i_period;
extern const char *g_tv_bluetech_id_cert_down_req_filename_1;
extern const char *g_tv_bluetech_id_cert_down_zipfile_1;
extern size_t g_tv_bluetech_id_cert_down_zipfile_size_1;
extern const char *g_tv_bluetech_id_cert_down_resp_1;
extern size_t g_tv_bluetech_id_cert_down_resp_size_1;
extern const char *g_tv_bluetech_id_cert_down_cmhf_name_1;
extern const char *g_tv_bluetech_id_cert_down_cmhf_1;
extern size_t g_tv_bluetech_id_cert_down_cmhf_size_1;
extern const char *g_tv_bluetech_id_cert_down_dir_name_1;
extern struct Dot2TestPseudonymIdCertDown g_tv_bluetech_id_cert_down_1;
extern const char *g_tv_bluetech_lv_crl_down;
extern size_t g_tv_bluetech_lv_crl_down_size;
extern unsigned int g_tv_bluetech_lv_crl_issue_date;
extern unsigned int g_tv_bluetech_lv_crl_next_crl;
extern unsigned int g_tv_bluetech_lv_crl_iRev;
extern unsigned int g_tv_bluetech_lv_crl_la1id;
extern unsigned int g_tv_bluetech_lv_crl_la2id;
extern unsigned int g_tv_bluetech_lv_crl_iMax;
extern const char *g_tv_bluetech_lv_crl_linkage_seed_1;
extern const char *g_tv_bluetech_lv_crl_linkage_seed_2;
extern unsigned int g_tv_bluetech_lv_crl_pseudonym_cert_1A9_i;
extern unsigned int g_tv_bluetech_lv_crl_pseudonym_cert_1A9_j;
extern const char *g_tv_bluetech_lv_crl_pseudonym_cert_1A9_linkage_value;
extern unsigned int g_tv_bluetech_lv_crl_pseudonym_cert_1AA_i;
extern unsigned int g_tv_bluetech_lv_crl_pseudonym_cert_1AA_j;
extern const char *g_tv_bluetech_lv_crl_pseudonym_cert_1AA_linkage_value;
extern const char *g_tv_bluetech_hash_crl_down;
extern size_t g_tv_bluetech_hash_crl_down_size;
extern unsigned int g_tv_bluetech_hash_crl_issue_date;
extern unsigned int g_tv_bluetech_hash_crl_next_crl;
extern const char *g_tv_bluetech_hash_crl_app_cert_h10;
extern unsigned int g_tv_bluetech_hash_crl_expiry;
extern const char *g_tv_bluetech_app_cert_h8;
extern const char *g_tv_bluetech_app_cert_spdu;
extern size_t g_tv_bluetech_app_cert_spdu_size;
extern const char *g_tv_bluetech_app_cert_digest_spdu;
extern size_t g_tv_bluetech_app_cert_digest_spdu_size;
extern const char *g_tv_bluetech_pseudonym_cert_1A9_h8;
extern const char *g_tv_bluetech_pseudonym_cert_1A9_spdu;
extern size_t g_tv_bluetech_pseudonym_cert_1A9_spdu_size;
extern const char *g_tv_bluetech_pseudonym_cert_1A9_digest_spdu;
extern size_t g_tv_bluetech_pseudonym_cert_1A9_digest_spdu_size;


/*
 * test-vector-lcm-ssotech.cc
 */
extern const char *g_tv_ssotech_lccf_1;
extern size_t g_tv_ssotech_lccf_1_size;


/*
 * test-vector-lcm-crosscert.cc
 */
extern const char *g_tv_crosscert_lccf_1;
extern size_t g_tv_crosscert_lccf_1_size;

#if 0

/*
 * 기타 유형 인증서 (SCMS에서 사용되지 않은 형식의 인증서들)
 */
extern uint8_t g_min_rectangular_region_cert[];
extern size_t g_min_rectangular_region_cert_size;
extern uint8_t g_max_rectangular_region_cert[];
extern size_t g_max_rectangular_region_cert_size;
extern uint8_t g_too_many_rectangular_region_cert[];
extern size_t g_too_many_rectangular_region_cert_size;
extern uint8_t g_min_polygonal_region_cert[];
extern size_t g_min_polygonal_region_cert_size;
extern uint8_t g_max_polygonal_region_cert[];
extern size_t g_max_polygonal_region_cert_size;
extern uint8_t g_too_many_polygonal_region_cert[];
extern size_t g_too_many_polygonal_region_cert_size;
extern uint8_t g_min_country_only_identified_region_cert[];
extern size_t g_min_country_only_identified_region_cert_size;
extern uint8_t g_max_country_only_identified_region_cert[];
extern size_t g_max_country_only_identified_region_cert_size;
extern uint8_t g_too_many_country_only_identified_region_cert[];
extern size_t g_too_many_country_only_identified_region_cert_size;
extern uint8_t g_min_country_and_regions_identified_region_cert[];
extern size_t g_min_country_and_regions_identified_region_cert_size;
extern uint8_t g_min_country_and_subregions_identified_region_cert[];
extern size_t g_min_country_and_subregions_identified_region_cert_size;
extern uint8_t g_simple_identified_region_cert[];
extern size_t g_simple_identified_region_cert_size;
extern uint8_t g_max_identified_region_cert[];
extern size_t g_max_identified_region_cert_size;
extern uint8_t g_too_many_identified_region_cert[];
extern size_t g_too_many_identified_region_cert_size;
extern uint8_t g_too_many_regions_cert[];
extern size_t g_too_many_regions_cert_size;
extern uint8_t g_too_many_region_and_subregion_cert[];
extern size_t g_too_many_region_and_subregion_cert_size;
extern uint8_t g_too_many_subregions_cert[];
extern size_t g_too_many_subregions_cert_size;
extern uint8_t g_usec_duration_cert[];
extern size_t g_usec_duration_cert_size;
extern uint8_t g_msec_duration_cert[];
extern size_t g_msec_duration_cert_size;
extern uint8_t g_sec_duration_cert[];
extern size_t g_sec_duration_cert_size;
extern uint8_t g_min_duration_cert[];
extern size_t g_min_duration_cert_size;
extern uint8_t g_sixty_hours_duration_cert[];
extern size_t g_sixty_hours_duration_cert_size;
extern uint8_t g_max_app_perms_cert[];
extern size_t g_max_app_perms_cert_size;
extern uint8_t g_many_app_perms_cert[];
extern size_t g_many_app_perms_cert_size;
extern uint8_t g_shortest_opaque_ssp_app_perms_cert[];
extern size_t g_shortest_opaque_ssp_app_perms_cert_size;
extern uint8_t g_longest_opaque_ssp_app_perms_cert[];
extern size_t g_longest_opaque_ssp_app_perms_cert_size;
extern uint8_t g_too_long_opaque_ssp_app_perms_cert[];
extern size_t g_too_long_opaque_ssp_app_perms_cert_size;
extern uint8_t g_shortest_bitmap_ssp_app_perms_cert[];
extern size_t g_shortest_bitmap_ssp_app_perms_cert_size;
extern uint8_t g_longest_bitmap_ssp_app_perms_cert[];
extern size_t g_longest_bitmap_ssp_app_perms_cert_size;
extern uint8_t g_max_cert_issue_perms_cert[];
extern size_t g_max_cert_issue_perms_cert_size;
extern uint8_t g_too_many_cert_issue_perms_cert[];
extern size_t g_too_many_cert_issue_perms_cert_size;
extern uint8_t g_max_psid_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_max_psid_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_too_many_psid_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_too_many_psid_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_max_opaque_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_max_opaque_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_too_many_opaque_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_too_many_opaque_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_longest_opaque_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_longest_opaque_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_too_long_opaque_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_too_long_opaque_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_shortest_bitmap_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_shortest_bitmap_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_longest_bitmap_ssp_range_explicit_cert_issue_perms_cert[];
extern size_t g_longest_bitmap_ssp_range_explicit_cert_issue_perms_cert_size;
extern uint8_t g_max_cert_req_perms_cert[];
extern size_t g_max_cert_req_perms_cert_size;
extern uint8_t g_too_many_cert_req_perms_cert[];
extern size_t g_too_many_cert_req_perms_cert_size;



#endif

#endif //V2X_SW_TEST_VECTORS_H
