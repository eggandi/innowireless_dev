/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 CA 인증서 관련 공통함수 정의
  * @date 2022-01-04 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "test-common-funcs.h"


/**
 * @brief 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
 */
void Dot2Test_AddCACerts()
{
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_rca_cert, g_sample_rca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_ica_cert, g_sample_ica_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_eca_cert, g_sample_eca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_pca_cert, g_sample_pca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_ra_cert, g_sample_ra_cert_size), 0);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5U);
}

#if 0
/**
 * @brief 샘플 RCA 인증서정보를 설정한다. g_sample_rca_cert 인증서에 해당됨.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleRCACertInfo(struct Dot2SCCCertInfoEntry *entry)
{
  memset(entry, 0, sizeof(struct Dot2SCCCertInfoEntry));
  entry->contents.common.issuer.type = kDot2CertIssuerIdentifierType_Self;
  entry->contents.common.valid_start = 468816349 * 1000000ULL;
  entry->contents.common.valid_end = (468816349 + (3600 * 24 * 365 * 40)) * 1000000ULL;
  entry->contents.common.verify_key_indicator.type = kDot2CertVerificationKeyIndicatorType_Key;
  memcpy(entry->contents.verify_pub_key.u.octs, g_sample_rca_cert_uncompressed_verification_key, DOT2_EC_256_PUB_KEY_LEN);
  memcpy(entry->cert_h.octs, g_sample_rca_cert_h, 32);
}


/**
 * @brief 샘플 ICA 인증서정보를 설정한다. g_sample_ica_cert 인증서에 해당됨.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * trusted와 verified는 상황에 따라 달라지기 때문에 여기서 설정할 수 없다.
 */
void Dot2Test_InitSampleICACertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_ica_cert_issuer_h8, 8);
  cert_info->valid_start = 468816349 * 1000000ULL;
  cert_info->valid_end = (468816349 + (3600 * 24 * 365 * 20)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 4;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 410;
  cert_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[1].u.country = 123;
  cert_info->valid_region.u.identified.region[2].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[2].u.country = 484;
  cert_info->valid_region.u.identified.region[3].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[3].u.country = 840;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 35;
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_Opaque;
  cert_info->app_perms[0].ssp.u.opaque.len = 3;
  cert_info->app_perms[0].ssp.u.opaque.ssp[0] = 0x83;
  cert_info->app_perms[0].ssp.u.opaque.ssp[1] = 0x00;
  cert_info->app_perms[0].ssp.u.opaque.ssp[2] = 0x01;
  cert_info->cert_issue_perms_num = 2;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_All;
  cert_info->cert_issue_perms[0].min_chain_depth = 2;
  cert_info->cert_issue_perms[0].chain_depth_range = 0;
  cert_info->cert_issue_perms[0].ee_type.app = true;
  cert_info->cert_issue_perms[0].ee_type.enrol = true;
  cert_info->cert_issue_perms[1].subject_perms.type = kDot2CertSubjectPermissionsType_Explicit;
  cert_info->cert_issue_perms[1].subject_perms.u.exp.num = 2;
  cert_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].psid = 35;
  cert_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present = true;
  cert_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range.type = kDot2CertSspRangeType_All;
  cert_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[1].psid = 256;
  cert_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[1].ssp_range_present = true;
  cert_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[1].ssp_range.type = kDot2CertSspRangeType_All;
  cert_info->cert_issue_perms[1].min_chain_depth = 1;
  cert_info->cert_issue_perms[1].chain_depth_range = -1;
  cert_info->cert_issue_perms[1].ee_type.app = true;
  cert_info->cert_issue_perms[1].ee_type.enrol = true;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_Key;
  cert_info->verify_key.u.key.type = kDot2CertPublicVerificationKeyType_EcdsaNistP256;
  memcpy(cert_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, g_sample_ica_cert_compressed_verification_key, 33);
  cert_info->signature.present = true;
  cert_info->signature.type = kDot2SignatureType_NISTp256;
  cert_info->signature.sign.nist_p256.R_r.u.point.form = kDot2EcPointP256Type_X_only;
  memcpy(cert_info->signature.sign.nist_p256.R_r.u.point.u.point, g_sample_ica_cert_r_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->signature.sign.nist_p256.s, g_sample_ica_cert_s_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->h, g_sample_ica_cert_h, 32);
  memcpy(cert_info->h8, g_sample_ica_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_ica_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_ica_cert_uncompressed_verification_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 샘플 ECA 인증서정보를 설정한다. g_sample_eca_cert 인증서에 해당됨.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * trusted와 verified는 상황에 따라 달라지기 때문에 여기서 설정할 수 없다.
 */
void Dot2Test_InitSampleECACertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_eca_cert_issuer_h8, 8);
  cert_info->valid_start = 468816349 * 1000000ULL;
  cert_info->valid_end = (468816349 + (3600 * 24 * 365 * 3)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 4;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 410;
  cert_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[1].u.country = 123;
  cert_info->valid_region.u.identified.region[2].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[2].u.country = 484;
  cert_info->valid_region.u.identified.region[3].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[3].u.country = 840;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 35;
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_Opaque;
  cert_info->app_perms[0].ssp.u.opaque.len = 3;
  cert_info->app_perms[0].ssp.u.opaque.ssp[0] = 0x84;
  cert_info->app_perms[0].ssp.u.opaque.ssp[1] = 0x00;
  cert_info->app_perms[0].ssp.u.opaque.ssp[2] = 0x01;
  cert_info->cert_issue_perms_num = 1;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_All;
  cert_info->cert_issue_perms[0].min_chain_depth = 1;
  cert_info->cert_issue_perms[0].chain_depth_range = 0;
  cert_info->cert_issue_perms[0].ee_type.app = false;
  cert_info->cert_issue_perms[0].ee_type.enrol = true;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_Key;
  cert_info->verify_key.u.key.type = kDot2CertPublicVerificationKeyType_EcdsaNistP256;
  memcpy(cert_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, g_sample_eca_cert_compressed_verification_key, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = true;
  cert_info->signature.type = kDot2SignatureType_NISTp256;
  cert_info->signature.sign.nist_p256.R_r.u.point.form = kDot2ECPointForm_X_only;
  memcpy(cert_info->signature.sign.nist_p256.R_r.u.point.u.point, g_sample_eca_cert_r_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->signature.sign.nist_p256.s, g_sample_eca_cert_s_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->h, g_sample_eca_cert_h, 32);
  memcpy(cert_info->h8, g_sample_eca_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_eca_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_eca_cert_uncompressed_verification_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 샘플 PCA 인증서정보를 설정한다. g_sample_pca_cert 인증서에 해당됨.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * trusted와 verified는 상황에 따라 달라지기 때문에 여기서 설정할 수 없다.
 */
void Dot2Test_InitSamplePCACertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_pca_cert_issuer_h8, 8);
  cert_info->valid_start = 468816349 * 1000000ULL;
  cert_info->valid_end = (468816349 + (3600 * 24 * 365 * 3)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 4;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 410;
  cert_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[1].u.country = 123;
  cert_info->valid_region.u.identified.region[2].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[2].u.country = 484;
  cert_info->valid_region.u.identified.region[3].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[3].u.country = 840;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 35;
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_Opaque;
  cert_info->app_perms[0].ssp.u.opaque.len = 3;
  cert_info->app_perms[0].ssp.u.opaque.ssp[0] = 0x85;
  cert_info->app_perms[0].ssp.u.opaque.ssp[1] = 0x00;
  cert_info->app_perms[0].ssp.u.opaque.ssp[2] = 0x01;
  cert_info->cert_issue_perms_num = 1;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_All;
  cert_info->cert_issue_perms[0].min_chain_depth = 1;
  cert_info->cert_issue_perms[0].chain_depth_range = 0;
  cert_info->cert_issue_perms[0].ee_type.app = true;
  cert_info->cert_issue_perms[0].ee_type.enrol = false;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_Key;
  cert_info->verify_key.u.key.type = kDot2CertPublicVerificationKeyType_EcdsaNistP256;
  memcpy(cert_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, g_sample_pca_cert_compressed_verification_key, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = true;
  cert_info->signature.type = kDot2SignatureType_NISTp256;
  cert_info->signature.sign.nist_p256.R_r.u.point.form = kDot2ECPointForm_X_only;
  memcpy(cert_info->signature.sign.nist_p256.R_r.u.point.u.point, g_sample_pca_cert_r_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->signature.sign.nist_p256.s, g_sample_pca_cert_s_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->h, g_sample_pca_cert_h, 32);
  memcpy(cert_info->h8, g_sample_pca_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_pca_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_pca_cert_uncompressed_verification_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 샘플 RA 인증서정보를 설정한다. g_sample_ra_cert 인증서에 해당됨.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * trusted와 verified는 상황에 따라 달라지기 때문에 여기서 설정할 수 없다.
 */
void Dot2Test_InitSampleRACertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_ra_cert_issuer_h8, 8);
  cert_info->valid_start = 468816349 * 1000000ULL;
  cert_info->valid_end = (468816349 + (3600 * 24 * 365 * 3)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 1;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 410;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 35;
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_Opaque;
  cert_info->app_perms[0].ssp.u.opaque.len = 3;
  cert_info->app_perms[0].ssp.u.opaque.ssp[0] = 0x8b;
  cert_info->app_perms[0].ssp.u.opaque.ssp[1] = 0x00;
  cert_info->app_perms[0].ssp.u.opaque.ssp[2] = 0x01;
  cert_info->cert_issue_perms_num = 0;
  cert_info->cert_req_perms_num = 1;
  cert_info->cert_req_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_All;
  cert_info->cert_req_perms[0].min_chain_depth = 0;
  cert_info->cert_req_perms[0].chain_depth_range = 0;
  cert_info->cert_req_perms[0].ee_type.app = true;
  cert_info->cert_req_perms[0].ee_type.enrol = false;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_Key;
  cert_info->verify_key.u.key.type = kDot2CertPublicVerificationKeyType_EcdsaNistP256;
  memcpy(cert_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, g_sample_ra_cert_compressed_verification_key, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = true;
  cert_info->signature.type = kDot2SignatureType_NISTp256;
  cert_info->signature.sign.nist_p256.R_r.u.point.form = kDot2ECPointForm_X_only;
  memcpy(cert_info->signature.sign.nist_p256.R_r.u.point.u.point, g_sample_ra_cert_r_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->signature.sign.nist_p256.s, g_sample_ra_cert_s_sig, DOT2_EC_KEY_MAX_LEN);
  memcpy(cert_info->h, g_sample_ra_cert_h, 32);
  memcpy(cert_info->h8, g_sample_ra_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_ra_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_ra_cert_uncompressed_verification_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief RCA 인증서정보엔트리에 저장된 정보와 샘플 RCA 인증서(g_sample_rca_cert) 정보가 동일한지 확인한다.
 * @param[in] rca_entry RCA 인증서정보엔트리
 * @param[in] sample_rca 샘플 RCA 인증서 데이터 (인코딩 바이트열)
 * @param[in] sample_rca_size 샘플 RCA 인증서 데이터 길이
 * @param[in] sample_rca_info 샘플 RCA 인증서 정보
 * @return 동일한지 여부
 *
 * trusted 와 verified 는 상황에 따라 달라질 수 있기 때문에, 본 함수에서 비교하지 않고 따로 비교한다.
 */
void Dot2Test_CompareRCACertInfo(
  struct Dot2CertEntry *rca_entry,
  uint8_t *sample_rca,
  Dot2CertSize sample_rca_size,
  struct Dot2CertInfo *sample_rca_info)
{
  ASSERT_EQ(rca_entry->cert_size, sample_rca_size);
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->cert, sample_rca, sample_rca_size));
  ASSERT_TRUE(rca_entry->issuer == nullptr);
  ASSERT_EQ(rca_entry->info.issuer.type, sample_rca_info->issuer.type);
  ASSERT_EQ(rca_entry->info.valid_start, sample_rca_info->valid_start);
  ASSERT_EQ(rca_entry->info.valid_end, sample_rca_info->valid_end);
  ASSERT_EQ(rca_entry->info.app_perms_num, sample_rca_info->app_perms_num);
  ASSERT_EQ(rca_entry->info.app_perms[0].psid, sample_rca_info->app_perms[0].psid);
  ASSERT_EQ(rca_entry->info.app_perms[0].ssp_present, sample_rca_info->app_perms[0].ssp_present);
  ASSERT_EQ(rca_entry->info.app_perms[0].ssp.type, sample_rca_info->app_perms[0].ssp.type);
  ASSERT_EQ(rca_entry->info.app_perms[0].ssp.u.opaque.len, sample_rca_info->app_perms[0].ssp.u.opaque.len);
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.app_perms[0].ssp.u.opaque.ssp, sample_rca_info->app_perms[0].ssp.u.opaque.ssp, rca_entry->info.app_perms[0].ssp.u.opaque.len));
  ASSERT_EQ(rca_entry->info.app_perms[1].psid, sample_rca_info->app_perms[1].psid);
  ASSERT_EQ(rca_entry->info.app_perms[1].ssp_present, sample_rca_info->app_perms[1].ssp_present);
  ASSERT_EQ(rca_entry->info.app_perms[1].ssp.type, sample_rca_info->app_perms[1].ssp.type);
  ASSERT_EQ(rca_entry->info.app_perms[1].ssp.u.opaque.len, sample_rca_info->app_perms[1].ssp.u.opaque.len);
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.app_perms[1].ssp.u.opaque.ssp, sample_rca_info->app_perms[1].ssp.u.opaque.ssp, rca_entry->info.app_perms[1].ssp.u.opaque.len));
  ASSERT_EQ(rca_entry->info.cert_issue_perms_num, sample_rca_info->cert_issue_perms_num);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[0].subject_perms.type, sample_rca_info->cert_issue_perms[0].subject_perms.type);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[0].min_chain_depth, sample_rca_info->cert_issue_perms[0].min_chain_depth);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[0].chain_depth_range, sample_rca_info->cert_issue_perms[0].chain_depth_range);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[0].ee_type.app, sample_rca_info->cert_issue_perms[0].ee_type.app);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[0].ee_type.enrol, sample_rca_info->cert_issue_perms[0].ee_type.enrol);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].subject_perms.type, sample_rca_info->cert_issue_perms[1].subject_perms.type);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].subject_perms.u.exp.num, sample_rca_info->cert_issue_perms[1].subject_perms.u.exp.num);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].psid,
            sample_rca_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].psid);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present,
            sample_rca_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].min_chain_depth, sample_rca_info->cert_issue_perms[1].min_chain_depth);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].chain_depth_range, sample_rca_info->cert_issue_perms[1].chain_depth_range);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].ee_type.app, sample_rca_info->cert_issue_perms[1].ee_type.app);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[1].ee_type.enrol, sample_rca_info->cert_issue_perms[1].ee_type.enrol);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].subject_perms.type, sample_rca_info->cert_issue_perms[2].subject_perms.type);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].subject_perms.u.exp.num, sample_rca_info->cert_issue_perms[2].subject_perms.u.exp.num);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].subject_perms.u.exp.psid_ssp_range[0].psid,
            sample_rca_info->cert_issue_perms[2].subject_perms.u.exp.psid_ssp_range[0].psid);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present,
            sample_rca_info->cert_issue_perms[2].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].min_chain_depth, sample_rca_info->cert_issue_perms[2].min_chain_depth);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].chain_depth_range, sample_rca_info->cert_issue_perms[2].chain_depth_range);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].ee_type.app, sample_rca_info->cert_issue_perms[2].ee_type.app);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[2].ee_type.enrol, sample_rca_info->cert_issue_perms[2].ee_type.enrol);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].subject_perms.type, sample_rca_info->cert_issue_perms[3].subject_perms.type);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].subject_perms.u.exp.num, sample_rca_info->cert_issue_perms[3].subject_perms.u.exp.num);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].subject_perms.u.exp.psid_ssp_range[0].psid,
            sample_rca_info->cert_issue_perms[3].subject_perms.u.exp.psid_ssp_range[0].psid);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present,
            sample_rca_info->cert_issue_perms[3].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].min_chain_depth, sample_rca_info->cert_issue_perms[3].min_chain_depth);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].chain_depth_range, sample_rca_info->cert_issue_perms[3].chain_depth_range);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].ee_type.app, sample_rca_info->cert_issue_perms[3].ee_type.app);
  ASSERT_EQ(rca_entry->info.cert_issue_perms[3].ee_type.enrol, sample_rca_info->cert_issue_perms[3].ee_type.enrol);
  ASSERT_EQ(rca_entry->info.cert_req_perms_num, sample_rca_info->cert_req_perms_num);
  ASSERT_EQ(rca_entry->info.verify_key.type, sample_rca_info->verify_key.type);
  ASSERT_EQ(rca_entry->info.verify_key.u.key.type, sample_rca_info->verify_key.u.key.type);
  ASSERT_EQ(rca_entry->info.verify_key.u.key.type, sample_rca_info->verify_key.u.key.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.verify_key.u.key.u.ecdsa_nist_p256.u.octets, sample_rca_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  ASSERT_EQ(rca_entry->info.signature.present, sample_rca_info->signature.present);
  ASSERT_EQ(rca_entry->info.signature.type, sample_rca_info->signature.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.signature.sign.nist_p256.R_r.u.octets, sample_rca_info->signature.sign.nist_p256.R_r.u.octets, 1 + DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.signature.sign.nist_p256.s, sample_rca_info->signature.sign.nist_p256.s, DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.h, sample_rca_info->h, 32));
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.h8, sample_rca_info->h8, 8));
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.h10, sample_rca_info->h10, 10));
  ASSERT_TRUE(Dot2Test_CompareOctets(rca_entry->info.verify_pub_key_pair.pub_key.u.octets, sample_rca_info->verify_pub_key_pair.pub_key.u.octets, DOT2_EC_PUB_KEY_MAX_LEN));
}


/**
 * @brief ICA 인증서정보엔트리에 저장된 정보와 샘플 ICA 인증서(g_sample_ica_cert) 정보가 동일한지 확인한다.
 * @param[in] ica_entry ICA 인증서정보엔트리
 * @param[in] sample_ica 샘플 ICA 인증서 데이터 (인코딩 바이트열)
 * @param[in] sample_ica_size 샘플 ICA 인증서 데이터 길이
 * @param[in] sample_ica_info 샘플 ICA 인증서 정보
 * @return 동일한지 여부
 *
 * trusted 와 verified 는 상황에 따라 달라질 수 있기 때문에, 본 함수에서 비교하지 않고 따로 비교한다.
 */
void Dot2Test_CompareICACertInfo(
  struct Dot2CertEntry *ica_entry,
  uint8_t *sample_ica,
  Dot2CertSize sample_ica_size,
  struct Dot2CertInfo *sample_ica_info)
{
  ASSERT_EQ(ica_entry->cert_size, sample_ica_size);
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->cert, sample_ica, sample_ica_size));
  ASSERT_EQ(ica_entry->info.issuer.type, sample_ica_info->issuer.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.issuer.hashedid8, sample_ica_info->issuer.hashedid8, 8));
  ASSERT_EQ(ica_entry->info.valid_start, sample_ica_info->valid_start);
  ASSERT_EQ(ica_entry->info.valid_end, sample_ica_info->valid_end);
  ASSERT_EQ(ica_entry->info.valid_region.present, sample_ica_info->valid_region.present);
  ASSERT_EQ(ica_entry->info.valid_region.type, sample_ica_info->valid_region.type);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region_num, sample_ica_info->valid_region.u.identified.region_num);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[0].type, sample_ica_info->valid_region.u.identified.region[0].type);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[0].u.country, sample_ica_info->valid_region.u.identified.region[0].u.country);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[1].type, sample_ica_info->valid_region.u.identified.region[1].type);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[1].u.country, sample_ica_info->valid_region.u.identified.region[1].u.country);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[2].type, sample_ica_info->valid_region.u.identified.region[2].type);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[2].u.country, sample_ica_info->valid_region.u.identified.region[2].u.country);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[3].type, sample_ica_info->valid_region.u.identified.region[3].type);
  ASSERT_EQ(ica_entry->info.valid_region.u.identified.region[3].u.country, sample_ica_info->valid_region.u.identified.region[3].u.country);
  ASSERT_EQ(ica_entry->info.app_perms_num, sample_ica_info->app_perms_num);
  ASSERT_EQ(ica_entry->info.app_perms[0].psid, sample_ica_info->app_perms[0].psid);
  ASSERT_EQ(ica_entry->info.app_perms[0].ssp_present, sample_ica_info->app_perms[0].ssp_present);
  ASSERT_EQ(ica_entry->info.app_perms[0].ssp.type, sample_ica_info->app_perms[0].ssp.type);
  ASSERT_EQ(ica_entry->info.app_perms[0].ssp.u.opaque.len, sample_ica_info->app_perms[0].ssp.u.opaque.len);
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.app_perms[0].ssp.u.opaque.ssp, sample_ica_info->app_perms[0].ssp.u.opaque.ssp, ica_entry->info.app_perms[0].ssp.u.opaque.len));
  ASSERT_EQ(ica_entry->info.cert_issue_perms_num, sample_ica_info->cert_issue_perms_num);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[0].subject_perms.type, sample_ica_info->cert_issue_perms[0].subject_perms.type);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[0].min_chain_depth, sample_ica_info->cert_issue_perms[0].min_chain_depth);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[0].chain_depth_range, sample_ica_info->cert_issue_perms[0].chain_depth_range);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[0].ee_type.app, sample_ica_info->cert_issue_perms[0].ee_type.app);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[0].ee_type.enrol, sample_ica_info->cert_issue_perms[0].ee_type.enrol);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].subject_perms.type, sample_ica_info->cert_issue_perms[1].subject_perms.type);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].subject_perms.u.exp.num, sample_ica_info->cert_issue_perms[1].subject_perms.u.exp.num);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].psid,
            sample_ica_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].psid);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present,
            sample_ica_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range_present);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range.type,
            sample_ica_info->cert_issue_perms[1].subject_perms.u.exp.psid_ssp_range[0].ssp_range.type);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].min_chain_depth, sample_ica_info->cert_issue_perms[1].min_chain_depth);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].chain_depth_range, sample_ica_info->cert_issue_perms[1].chain_depth_range);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].ee_type.app, sample_ica_info->cert_issue_perms[1].ee_type.app);
  ASSERT_EQ(ica_entry->info.cert_issue_perms[1].ee_type.enrol, sample_ica_info->cert_issue_perms[1].ee_type.enrol);
  ASSERT_EQ(ica_entry->info.cert_req_perms_num, sample_ica_info->cert_req_perms_num);
  ASSERT_EQ(ica_entry->info.verify_key.type, sample_ica_info->verify_key.type);
  ASSERT_EQ(ica_entry->info.verify_key.u.key.type, sample_ica_info->verify_key.u.key.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.verify_key.u.key.u.ecdsa_nist_p256.u.octets, sample_ica_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  ASSERT_EQ(ica_entry->info.signature.present, sample_ica_info->signature.present);
  ASSERT_EQ(ica_entry->info.signature.type, sample_ica_info->signature.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.signature.sign.nist_p256.R_r.u.octets, sample_ica_info->signature.sign.nist_p256.R_r.u.octets, 1 + DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.signature.sign.nist_p256.s, sample_ica_info->signature.sign.nist_p256.s, DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.h, sample_ica_info->h, 32));
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.h8, sample_ica_info->h8, 8));
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.h10, sample_ica_info->h10, 10));
  ASSERT_TRUE(Dot2Test_CompareOctets(ica_entry->info.verify_pub_key_pair.pub_key.u.octets, sample_ica_info->verify_pub_key_pair.pub_key.u.octets, DOT2_EC_PUB_KEY_MAX_LEN));
}


/**
 * @brief ECA 인증서정보엔트리에 저장된 정보와 샘플 ECA 인증서(g_sample_eca_cert) 정보가 동일한지 확인한다.
 * @param[in] eca_entry ECA 인증서정보엔트리
 * @param[in] sample_eca 샘플 ECA 인증서 데이터 (인코딩 바이트열)
 * @param[in] sample_eca_size 샘플 ECA 인증서 데이터 길이
 * @param[in] sample_eca_info 샘플 ECA 인증서 정보
 * @return 동일한지 여부
 *
 * trusted 와 verified 는 상황에 따라 달라질 수 있기 때문에, 본 함수에서 비교하지 않고 따로 비교한다.
 */
void Dot2Test_CompareECACertInfo(
  struct Dot2CertEntry *eca_entry,
  uint8_t *sample_eca,
  Dot2CertSize sample_eca_size,
  struct Dot2CertInfo *sample_eca_info)
{
  ASSERT_EQ(eca_entry->cert_size, sample_eca_size);
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->cert, sample_eca, sample_eca_size));
  ASSERT_EQ(eca_entry->info.issuer.type, sample_eca_info->issuer.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.issuer.hashedid8, sample_eca_info->issuer.hashedid8, 8));
  ASSERT_EQ(eca_entry->info.valid_start, sample_eca_info->valid_start);
  ASSERT_EQ(eca_entry->info.valid_end, sample_eca_info->valid_end);
  ASSERT_EQ(eca_entry->info.valid_region.present, sample_eca_info->valid_region.present);
  ASSERT_EQ(eca_entry->info.valid_region.type, sample_eca_info->valid_region.type);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region_num, sample_eca_info->valid_region.u.identified.region_num);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[0].type, sample_eca_info->valid_region.u.identified.region[0].type);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[0].u.country, sample_eca_info->valid_region.u.identified.region[0].u.country);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[1].type, sample_eca_info->valid_region.u.identified.region[1].type);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[1].u.country, sample_eca_info->valid_region.u.identified.region[1].u.country);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[2].type, sample_eca_info->valid_region.u.identified.region[2].type);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[2].u.country, sample_eca_info->valid_region.u.identified.region[2].u.country);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[3].type, sample_eca_info->valid_region.u.identified.region[3].type);
  ASSERT_EQ(eca_entry->info.valid_region.u.identified.region[3].u.country, sample_eca_info->valid_region.u.identified.region[3].u.country);
  ASSERT_EQ(eca_entry->info.app_perms_num, sample_eca_info->app_perms_num);
  ASSERT_EQ(eca_entry->info.app_perms[0].psid, sample_eca_info->app_perms[0].psid);
  ASSERT_EQ(eca_entry->info.app_perms[0].ssp_present, sample_eca_info->app_perms[0].ssp_present);
  ASSERT_EQ(eca_entry->info.app_perms[0].ssp.type, sample_eca_info->app_perms[0].ssp.type);
  ASSERT_EQ(eca_entry->info.app_perms[0].ssp.u.opaque.len, sample_eca_info->app_perms[0].ssp.u.opaque.len);
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.app_perms[0].ssp.u.opaque.ssp, sample_eca_info->app_perms[0].ssp.u.opaque.ssp, eca_entry->info.app_perms[0].ssp.u.opaque.len));
  ASSERT_EQ(eca_entry->info.cert_issue_perms_num, sample_eca_info->cert_issue_perms_num);
  ASSERT_EQ(eca_entry->info.cert_issue_perms[0].subject_perms.type, sample_eca_info->cert_issue_perms[0].subject_perms.type);
  ASSERT_EQ(eca_entry->info.cert_issue_perms[0].min_chain_depth, sample_eca_info->cert_issue_perms[0].min_chain_depth);
  ASSERT_EQ(eca_entry->info.cert_issue_perms[0].chain_depth_range, sample_eca_info->cert_issue_perms[0].chain_depth_range);
  ASSERT_EQ(eca_entry->info.cert_issue_perms[0].ee_type.app, sample_eca_info->cert_issue_perms[0].ee_type.app);
  ASSERT_EQ(eca_entry->info.cert_issue_perms[0].ee_type.enrol, sample_eca_info->cert_issue_perms[0].ee_type.enrol);
  ASSERT_EQ(eca_entry->info.cert_req_perms_num, sample_eca_info->cert_req_perms_num);
  ASSERT_EQ(eca_entry->info.verify_key.type, sample_eca_info->verify_key.type);
  ASSERT_EQ(eca_entry->info.verify_key.u.key.type, sample_eca_info->verify_key.u.key.type);
  ASSERT_EQ(eca_entry->info.verify_key.u.key.type, sample_eca_info->verify_key.u.key.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.verify_key.u.key.u.ecdsa_nist_p256.u.octets, sample_eca_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  ASSERT_EQ(eca_entry->info.signature.present, sample_eca_info->signature.present);
  ASSERT_EQ(eca_entry->info.signature.type, sample_eca_info->signature.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.signature.sign.nist_p256.R_r.u.octets, sample_eca_info->signature.sign.nist_p256.R_r.u.octets, 1 + DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.signature.sign.nist_p256.s, sample_eca_info->signature.sign.nist_p256.s, DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.h, sample_eca_info->h, 32));
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.h8, sample_eca_info->h8, 8));
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.h10, sample_eca_info->h10, 10));
  ASSERT_TRUE(Dot2Test_CompareOctets(eca_entry->info.verify_pub_key_pair.pub_key.u.octets, sample_eca_info->verify_pub_key_pair.pub_key.u.octets, DOT2_EC_PUB_KEY_MAX_LEN));
}


/**
 * @brief PCA 인증서정보엔트리에 저장된 정보와 샘플 PCA 인증서(g_sample_pca_cert) 정보가 동일한지 확인한다.
 * @param[in] pca_entry PCA 인증서정보엔트리
 * @param[in] sample_pca 샘플 PCA 인증서 데이터 (인코딩 바이트열)
 * @param[in] sample_pca_size 샘플 PCA 인증서 데이터 길이
 * @param[in] sample_pca_info 샘플 PCA 인증서 정보
 * @return 동일한지 여부
 *
 * trusted 와 verified 는 상황에 따라 달라질 수 있기 때문에, 본 함수에서 비교하지 않고 따로 비교한다.
 */
void Dot2Test_ComparePCACertInfo(
  struct Dot2CertEntry *pca_entry,
  uint8_t *sample_pca,
  Dot2CertSize sample_pca_size,
  struct Dot2CertInfo *sample_pca_info)
{
  ASSERT_EQ(pca_entry->cert_size, sample_pca_size);
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->cert, sample_pca, sample_pca_size));
  ASSERT_EQ(pca_entry->info.issuer.type, sample_pca_info->issuer.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.issuer.hashedid8, sample_pca_info->issuer.hashedid8, 8));
  ASSERT_EQ(pca_entry->info.valid_start, sample_pca_info->valid_start);
  ASSERT_EQ(pca_entry->info.valid_end, sample_pca_info->valid_end);
  ASSERT_EQ(pca_entry->info.valid_region.present, sample_pca_info->valid_region.present);
  ASSERT_EQ(pca_entry->info.valid_region.type, sample_pca_info->valid_region.type);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region_num, sample_pca_info->valid_region.u.identified.region_num);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[0].type, sample_pca_info->valid_region.u.identified.region[0].type);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[0].u.country, sample_pca_info->valid_region.u.identified.region[0].u.country);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[1].type, sample_pca_info->valid_region.u.identified.region[1].type);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[1].u.country, sample_pca_info->valid_region.u.identified.region[1].u.country);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[2].type, sample_pca_info->valid_region.u.identified.region[2].type);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[2].u.country, sample_pca_info->valid_region.u.identified.region[2].u.country);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[3].type, sample_pca_info->valid_region.u.identified.region[3].type);
  ASSERT_EQ(pca_entry->info.valid_region.u.identified.region[3].u.country, sample_pca_info->valid_region.u.identified.region[3].u.country);
  ASSERT_EQ(pca_entry->info.app_perms_num, sample_pca_info->app_perms_num);
  ASSERT_EQ(pca_entry->info.app_perms[0].psid, sample_pca_info->app_perms[0].psid);
  ASSERT_EQ(pca_entry->info.app_perms[0].ssp_present, sample_pca_info->app_perms[0].ssp_present);
  ASSERT_EQ(pca_entry->info.app_perms[0].ssp.type, sample_pca_info->app_perms[0].ssp.type);
  ASSERT_EQ(pca_entry->info.app_perms[0].ssp.u.opaque.len, sample_pca_info->app_perms[0].ssp.u.opaque.len);
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.app_perms[0].ssp.u.opaque.ssp, sample_pca_info->app_perms[0].ssp.u.opaque.ssp, pca_entry->info.app_perms[0].ssp.u.opaque.len));
  ASSERT_EQ(pca_entry->info.cert_issue_perms_num, sample_pca_info->cert_issue_perms_num);
  ASSERT_EQ(pca_entry->info.cert_issue_perms[0].subject_perms.type, sample_pca_info->cert_issue_perms[0].subject_perms.type);
  ASSERT_EQ(pca_entry->info.cert_issue_perms[0].min_chain_depth, sample_pca_info->cert_issue_perms[0].min_chain_depth);
  ASSERT_EQ(pca_entry->info.cert_issue_perms[0].chain_depth_range, sample_pca_info->cert_issue_perms[0].chain_depth_range);
  ASSERT_EQ(pca_entry->info.cert_issue_perms[0].ee_type.app, sample_pca_info->cert_issue_perms[0].ee_type.app);
  ASSERT_EQ(pca_entry->info.cert_issue_perms[0].ee_type.enrol, sample_pca_info->cert_issue_perms[0].ee_type.enrol);
  ASSERT_EQ(pca_entry->info.cert_req_perms_num, sample_pca_info->cert_req_perms_num);
  ASSERT_EQ(pca_entry->info.verify_key.type, sample_pca_info->verify_key.type);
  ASSERT_EQ(pca_entry->info.verify_key.u.key.type, sample_pca_info->verify_key.u.key.type);
  ASSERT_EQ(pca_entry->info.verify_key.u.key.type, sample_pca_info->verify_key.u.key.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.verify_key.u.key.u.ecdsa_nist_p256.u.octets, sample_pca_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  ASSERT_EQ(pca_entry->info.signature.present, sample_pca_info->signature.present);
  ASSERT_EQ(pca_entry->info.signature.type, sample_pca_info->signature.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.signature.sign.nist_p256.R_r.u.octets, sample_pca_info->signature.sign.nist_p256.R_r.u.octets, 1 + DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.signature.sign.nist_p256.s, sample_pca_info->signature.sign.nist_p256.s, DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.h, sample_pca_info->h, 32));
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.h8, sample_pca_info->h8, 8));
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.h10, sample_pca_info->h10, 10));
  ASSERT_TRUE(Dot2Test_CompareOctets(pca_entry->info.verify_pub_key_pair.pub_key.u.octets, sample_pca_info->verify_pub_key_pair.pub_key.u.octets, DOT2_EC_PUB_KEY_MAX_LEN));
}


/**
 * @brief RA 인증서정보엔트리에 저장된 정보와 샘플 RA 인증서(g_sample_ra_cert) 정보가 동일한지 확인한다.
 * @param[in] ra_entry RA 인증서정보엔트리
 * @param[in] sample_ra 샘플 RA 인증서 데이터 (인코딩 바이트열)
 * @param[in] sample_ra_size 샘플 RA 인증서 데이터 길이
 * @param[in] sample_ra_info 샘플 RA 인증서 정보
 * @return 동일한지 여부
 *
 * trusted 와 verified 는 상황에 따라 달라질 수 있기 때문에, 본 함수에서 비교하지 않고 따로 비교한다.
 */
void Dot2Test_CompareRACertInfo(
  struct Dot2CertEntry *ra_entry,
  uint8_t *sample_ra,
  Dot2CertSize sample_ra_size,
  struct Dot2CertInfo *sample_ra_info)
{
  ASSERT_EQ(ra_entry->cert_size, sample_ra_size);
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->cert, sample_ra, sample_ra_size));
  ASSERT_EQ(ra_entry->info.issuer.type, sample_ra_info->issuer.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.issuer.hashedid8, sample_ra_info->issuer.hashedid8, 8));
  ASSERT_EQ(ra_entry->info.valid_start, sample_ra_info->valid_start);
  ASSERT_EQ(ra_entry->info.valid_end, sample_ra_info->valid_end);
  ASSERT_EQ(ra_entry->info.valid_region.present, sample_ra_info->valid_region.present);
  ASSERT_EQ(ra_entry->info.valid_region.type, sample_ra_info->valid_region.type);
  ASSERT_EQ(ra_entry->info.valid_region.u.identified.region_num, sample_ra_info->valid_region.u.identified.region_num);
  ASSERT_EQ(ra_entry->info.valid_region.u.identified.region[0].type, sample_ra_info->valid_region.u.identified.region[0].type);
  ASSERT_EQ(ra_entry->info.valid_region.u.identified.region[0].u.country, sample_ra_info->valid_region.u.identified.region[0].u.country);
  ASSERT_EQ(ra_entry->info.app_perms_num, sample_ra_info->app_perms_num);
  ASSERT_EQ(ra_entry->info.app_perms[0].psid, sample_ra_info->app_perms[0].psid);
  ASSERT_EQ(ra_entry->info.app_perms[0].ssp_present, sample_ra_info->app_perms[0].ssp_present);
  ASSERT_EQ(ra_entry->info.app_perms[0].ssp.type, sample_ra_info->app_perms[0].ssp.type);
  ASSERT_EQ(ra_entry->info.app_perms[0].ssp.u.opaque.len, sample_ra_info->app_perms[0].ssp.u.opaque.len);
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.app_perms[0].ssp.u.opaque.ssp, sample_ra_info->app_perms[0].ssp.u.opaque.ssp, ra_entry->info.app_perms[0].ssp.u.opaque.len));
  ASSERT_EQ(ra_entry->info.cert_issue_perms_num, sample_ra_info->cert_issue_perms_num);
  ASSERT_EQ(ra_entry->info.cert_req_perms_num, sample_ra_info->cert_req_perms_num);
  ASSERT_EQ(ra_entry->info.cert_req_perms[0].subject_perms.type, sample_ra_info->cert_req_perms[0].subject_perms.type);
  ASSERT_EQ(ra_entry->info.cert_req_perms[0].min_chain_depth, sample_ra_info->cert_req_perms[0].min_chain_depth);
  ASSERT_EQ(ra_entry->info.cert_req_perms[0].chain_depth_range, sample_ra_info->cert_req_perms[0].chain_depth_range);
  ASSERT_EQ(ra_entry->info.cert_req_perms[0].ee_type.app, sample_ra_info->cert_req_perms[0].ee_type.app);
  ASSERT_EQ(ra_entry->info.cert_req_perms[0].ee_type.enrol, sample_ra_info->cert_req_perms[0].ee_type.enrol);
  ASSERT_EQ(ra_entry->info.verify_key.type, sample_ra_info->verify_key.type);
  ASSERT_EQ(ra_entry->info.verify_key.u.key.type, sample_ra_info->verify_key.u.key.type);
  ASSERT_EQ(ra_entry->info.verify_key.u.key.type, sample_ra_info->verify_key.u.key.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.verify_key.u.key.u.ecdsa_nist_p256.u.octets, sample_ra_info->verify_key.u.key.u.ecdsa_nist_p256.u.octets, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN));
  ASSERT_EQ(ra_entry->info.signature.present, sample_ra_info->signature.present);
  ASSERT_EQ(ra_entry->info.signature.type, sample_ra_info->signature.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.signature.sign.nist_p256.R_r.u.octets, sample_ra_info->signature.sign.nist_p256.R_r.u.octets, 1 + DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.signature.sign.nist_p256.s, sample_ra_info->signature.sign.nist_p256.s, DOT2_EC_256_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.h, sample_ra_info->h, 32));
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.h8, sample_ra_info->h8, 8));
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.h10, sample_ra_info->h10, 10));
  ASSERT_TRUE(Dot2Test_CompareOctets(ra_entry->info.verify_pub_key_pair.pub_key.u.octets, sample_ra_info->verify_pub_key_pair.pub_key.u.octets, DOT2_EC_PUB_KEY_MAX_LEN));
}
#endif
