/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 기타 인증서 관련 공통함수 정의
  * @date 2022-01-04 
  * @author gyun
  *
  * 본 파일에 정의된 인증서들은 정규 인증서가 아니라, 단위테스트를 위해 일부 필드를 임의로 조작한 인증서이다.
  * 따라서, 키 재구성이나 서명 검증 등 인증서 내용이 변경되면 안되는 기능들에 대한 테스트에는 적용할 수 없다.
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "test-common-funcs.h"

#if 0

/**
 * @brief 최소개수 rectanguarl region을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_min_rectangular_region_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMinRectangularRegionCertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_rse_0_cert_issuer_h8, 8);
  cert_info->valid_start = 499525388 * 1000000ULL;
  cert_info->valid_end = (499525388 + (3600 * 850)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_RectangularSet;
  cert_info->valid_region.u.rectangular.region_num = 1;
  cert_info->valid_region.u.rectangular.region[0].north_west.lat = 374856150;
  cert_info->valid_region.u.rectangular.region[0].north_west.lon = 1270392830;
  cert_info->valid_region.u.rectangular.region[0].south_east.lat = 374856150;
  cert_info->valid_region.u.rectangular.region[0].south_east.lon = 1270392830;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 135;
  cert_info->app_perms[0].ssp_present = false;
  cert_info->cert_issue_perms_num = 0;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_ReconstructValue;
  memcpy(cert_info->verify_key.u.recon_pub.u.octets, g_sample_rse_0_cert_reconstruct_value, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = false;
  memcpy(cert_info->h, g_sample_rse_0_cert_h, 32);
  memcpy(cert_info->h8, g_sample_rse_0_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_rse_0_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_rse_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 최대개수 rectanguarl region을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_max_rectangular_region_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMaxRectangularRegionCertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_rse_0_cert_issuer_h8, 8);
  cert_info->valid_start = 499525388 * 1000000ULL;
  cert_info->valid_end = (499525388 + (3600 * 850)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_RectangularSet;
  cert_info->valid_region.u.rectangular.region_num = 8;
  cert_info->valid_region.u.rectangular.region[0].north_west.lat = 374856151;
  cert_info->valid_region.u.rectangular.region[0].north_west.lon = 1270392831;
  cert_info->valid_region.u.rectangular.region[0].south_east.lat = 374856141;
  cert_info->valid_region.u.rectangular.region[0].south_east.lon = 1270392841;
  cert_info->valid_region.u.rectangular.region[1].north_west.lat = 374856152;
  cert_info->valid_region.u.rectangular.region[1].north_west.lon = 1270392832;
  cert_info->valid_region.u.rectangular.region[1].south_east.lat = 374856142;
  cert_info->valid_region.u.rectangular.region[1].south_east.lon = 1270392842;
  cert_info->valid_region.u.rectangular.region[2].north_west.lat = 374856153;
  cert_info->valid_region.u.rectangular.region[2].north_west.lon = 1270392833;
  cert_info->valid_region.u.rectangular.region[2].south_east.lat = 374856143;
  cert_info->valid_region.u.rectangular.region[2].south_east.lon = 1270392843;
  cert_info->valid_region.u.rectangular.region[3].north_west.lat = 374856154;
  cert_info->valid_region.u.rectangular.region[3].north_west.lon = 1270392834;
  cert_info->valid_region.u.rectangular.region[3].south_east.lat = 374856144;
  cert_info->valid_region.u.rectangular.region[3].south_east.lon = 1270392844;
  cert_info->valid_region.u.rectangular.region[4].north_west.lat = 374856155;
  cert_info->valid_region.u.rectangular.region[4].north_west.lon = 1270392835;
  cert_info->valid_region.u.rectangular.region[4].south_east.lat = 374856145;
  cert_info->valid_region.u.rectangular.region[4].south_east.lon = 1270392845;
  cert_info->valid_region.u.rectangular.region[5].north_west.lat = 374856156;
  cert_info->valid_region.u.rectangular.region[5].north_west.lon = 1270392836;
  cert_info->valid_region.u.rectangular.region[5].south_east.lat = 374856146;
  cert_info->valid_region.u.rectangular.region[5].south_east.lon = 1270392846;
  cert_info->valid_region.u.rectangular.region[6].north_west.lat = 374856157;
  cert_info->valid_region.u.rectangular.region[6].north_west.lon = 1270392837;
  cert_info->valid_region.u.rectangular.region[6].south_east.lat = 374856147;
  cert_info->valid_region.u.rectangular.region[6].south_east.lon = 1270392847;
  cert_info->valid_region.u.rectangular.region[7].north_west.lat = 374856158;
  cert_info->valid_region.u.rectangular.region[7].north_west.lon = 1270392838;
  cert_info->valid_region.u.rectangular.region[7].south_east.lat = 374856148;
  cert_info->valid_region.u.rectangular.region[7].south_east.lon = 1270392848;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 135;
  cert_info->app_perms[0].ssp_present = false;
  cert_info->cert_issue_perms_num = 0;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_ReconstructValue;
  memcpy(cert_info->verify_key.u.recon_pub.u.octets, g_sample_rse_0_cert_reconstruct_value, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = false;
  memcpy(cert_info->h, g_sample_rse_0_cert_h, 32);
  memcpy(cert_info->h8, g_sample_rse_0_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_rse_0_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_rse_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 최소개수(1) countryOnly identified region을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_min_country_only_identified_region_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_rse_0_cert_issuer_h8, 8);
  cert_info->valid_start = 499525388 * 1000000ULL;
  cert_info->valid_end = (499525388 + (3600 * 850)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 1;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 180;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 135;
  cert_info->app_perms[0].ssp_present = false;
  cert_info->cert_issue_perms_num = 0;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_ReconstructValue;
  memcpy(cert_info->verify_key.u.recon_pub.u.octets, g_sample_rse_0_cert_reconstruct_value, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = false;
  memcpy(cert_info->h, g_sample_rse_0_cert_h, 32);
  memcpy(cert_info->h8, g_sample_rse_0_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_rse_0_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_rse_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 최대개수(kDot2IdentifiedRegionNum_Max=8) countryOnly identified region을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_max_country_only_identified_region_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMaxCountryOnlyIdentifiedRegionCertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_rse_0_cert_issuer_h8, 8);
  cert_info->valid_start = 499525388 * 1000000ULL;
  cert_info->valid_end = (499525388 + (3600 * 850)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 8;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 180;
  cert_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[1].u.country = 181;
  cert_info->valid_region.u.identified.region[2].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[2].u.country = 182;
  cert_info->valid_region.u.identified.region[3].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[3].u.country = 183;
  cert_info->valid_region.u.identified.region[4].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[4].u.country = 184;
  cert_info->valid_region.u.identified.region[5].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[5].u.country = 185;
  cert_info->valid_region.u.identified.region[6].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[6].u.country = 186;
  cert_info->valid_region.u.identified.region[7].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[7].u.country = 187;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 135;
  cert_info->app_perms[0].ssp_present = false;
  cert_info->cert_issue_perms_num = 0;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_ReconstructValue;
  memcpy(cert_info->verify_key.u.recon_pub.u.octets, g_sample_rse_0_cert_reconstruct_value, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = false;
  memcpy(cert_info->h, g_sample_rse_0_cert_h, 32);
  memcpy(cert_info->h8, g_sample_rse_0_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_rse_0_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_rse_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief microseconds 유형의 Duration을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_usec_duration_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleUsecDurationCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->valid_end = (499525388 * 1000000ULL) + 850ULL;
}


/**
 * @brief milliseconds 유형의 Duration을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_msec_duration_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMsecDurationCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->valid_end = (499525388 * 1000000ULL) + (850 * 1000ULL);
}


/**
 * @brief seconds 유형의 Duration을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_sec_duration_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleSecDurationCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->valid_end = (499525388 + 850) * 1000000ULL;
}


/**
 * @brief minutes 유형의 Duration을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_min_duration_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMinuteDurationCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->valid_end = (499525388 * 1000000ULL) + (850 * 60 * 1000000ULL);
}


/**
 * @brief sixtyHours 유형의 Duration을 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_sixty_hours_duration_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleSixtyHoursDurationCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->valid_end = (499525388 * 1000000ULL) + (10 * 60 * 3600 * 1000000ULL);
}


/**
 * @brief 최대개수(kDot2CertPermissionNum_Max=20) appPermissions를 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_max_app_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMaxAppPermsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->app_perms_num = 20;
  for (unsigned int i = 0; i < cert_info->app_perms_num; i++) {
    cert_info->app_perms[i].psid = 135 + i;
    cert_info->app_perms[i].ssp_present = false;
  }
}


/**
 * @brief 최소길이(0) opaque SSP를 갖는 appPermissions를 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_shortest_opaque_ssp_app_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleShortestOpaqueSspAppPermsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_Opaque;
  cert_info->app_perms[0].ssp.u.opaque.len = 0;
}


/**
 * @brief 최대길이(kDot2CertSspLen_Max=31) opaque SSP를 갖는 appPermissions를 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_longest_opaque_ssp_app_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleLongestOpaqueSspAppPermsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_Opaque;
  cert_info->app_perms[0].ssp.u.opaque.len = 31;
  for (unsigned int i = 0; i < cert_info->app_perms[0].ssp.u.opaque.len; i++) {
    cert_info->app_perms[0].ssp.u.opaque.ssp[i] = i % 10;
  }
}


/**
 * @brief 최소길이(0) bitmapSspP를 갖는 appPermissions를 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_shortest_bitmap_ssp_app_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleShortestBitmapSspAppPermsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_BitmapSsp;
  cert_info->app_perms[0].ssp.u.bitmap_ssp.len = 0;
}


/**
 * @brief 최대길이(kDot2CertSspLen_Max=31) bitmapSsp를 갖는 appPermissions를 포함한 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * rse-0 인증서의 내용을 임의로 조작한 g_longest_bitmap_ssp_app_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleLongestBitmapSspAppPermsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleMinCountryOnlyIdentifiedRegionCertInfo(cert_info);
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.type = kDot2CertSspType_BitmapSsp;
  cert_info->app_perms[0].ssp.u.bitmap_ssp.len = 31;
  for (unsigned int i = 0; i < cert_info->app_perms[0].ssp.u.bitmap_ssp.len; i++) {
    cert_info->app_perms[0].ssp.u.bitmap_ssp.ssp[i] = i % 10;
  }
}


/**
 * @brief certIssuePermissions 관련 테스트를 위한 샘플 ICA 인증서정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_ica_cert_issuer_h8, 8);
  cert_info->valid_start = 468816349 * 1000000ULL;
  cert_info->valid_end = (468816349 + (3600 * 24 * 365 * 20)) * 1000000ULL;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 1;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 410;
  cert_info->app_perms_num = 1;
  cert_info->app_perms[0].psid = 35;
  cert_info->app_perms[0].ssp_present = true;
  cert_info->app_perms[0].ssp.u.opaque.len = 3;
  cert_info->app_perms[0].ssp.u.opaque.ssp[0] = 0x83;
  cert_info->app_perms[0].ssp.u.opaque.ssp[1] = 0x00;
  cert_info->app_perms[0].ssp.u.opaque.ssp[2] = 0x01;
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
 * @brief 최대개수(kDot2CertPermissionNum_Max=20) certIssuePermissions를 포함한 인증서 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * ica 인증서의 내용을 임의로 조작한 g_max_cert_issue_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMaxCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleCertIssuePermissionsCertInfo(cert_info);
  cert_info->cert_issue_perms_num = 20;
  for (unsigned int i = 0; i < cert_info->cert_issue_perms_num; i++) {
    cert_info->cert_issue_perms[i].subject_perms.type = kDot2CertSubjectPermissionsType_All;
    cert_info->cert_issue_perms[i].min_chain_depth = 2;
    cert_info->cert_issue_perms[i].chain_depth_range = 0;
    cert_info->cert_issue_perms[i].ee_type.app = true;
    cert_info->cert_issue_perms[i].ee_type.enrol = true;
  }
}


/**
 * @brief 최대개수(kDot2CertPsidSspRangeNum_Max=8) PsidSspRange를 포함한 explicit 형식 certIssuePermissions를 포함한 인증서 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * ica 인증서의 내용을 임의로 조작한 g_max_psid_ssp_range_explicit_cert_issue_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMaxPsidSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleCertIssuePermissionsCertInfo(cert_info);
  cert_info->cert_issue_perms_num = 1;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_Explicit;
  cert_info->cert_issue_perms[0].subject_perms.u.exp.num = 8;
  for (unsigned int i = 0; i < cert_info->cert_issue_perms[0].subject_perms.u.exp.num; i++) {
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].psid = 10 + i;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range_present = true;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.type = kDot2CertSspRangeType_All;
  }
  cert_info->cert_issue_perms[0].min_chain_depth = 1;
  cert_info->cert_issue_perms[0].chain_depth_range = -1;
  cert_info->cert_issue_perms[0].ee_type.app = true;
  cert_info->cert_issue_perms[0].ee_type.enrol = true;
}


/**
 * @brief 최대개수(kDot2CertSspNum_Max=8) opaque SspRange를 포함한 explicit 형식 certIssuePermissions를 포함한 인증서 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * ica 인증서의 내용을 임의로 조작한 g_max_opaque_ssp_range_explicit_cert_issue_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMaxOpaqueSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleCertIssuePermissionsCertInfo(cert_info);
  cert_info->cert_issue_perms_num = 1;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_Explicit;
  cert_info->cert_issue_perms[0].subject_perms.u.exp.num = 1;
  for (unsigned int i = 0; i < cert_info->cert_issue_perms[0].subject_perms.u.exp.num; i++) {
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].psid = 10 + i;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range_present = true;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.type = kDot2CertSspRangeType_Opaque;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp_num = 8;
    for (unsigned int j = 0; j < cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp_num; j++) {
      cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp[j].len = 3;
      cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp[j].ssp[0] = 0x83;
      cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp[j].ssp[1] = 0x00;
      cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp[j].ssp[2] = 0x01 + j;
    }
  }
  cert_info->cert_issue_perms[0].min_chain_depth = 1;
  cert_info->cert_issue_perms[0].chain_depth_range = -1;
  cert_info->cert_issue_perms[0].ee_type.app = true;
  cert_info->cert_issue_perms[0].ee_type.enrol = true;
}


/**
 * @brief 최대길이(kDot2CertSspLen_Max=31) opaque SspRange를 포함한 explicit 형식 certIssuePermissions를 포함한 인증서 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * ica 인증서의 내용을 임의로 조작한 g_longest_opaque_ssp_range_explicit_cert_issue_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleLongestOpaqueSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleCertIssuePermissionsCertInfo(cert_info);
  cert_info->cert_issue_perms_num = 1;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_Explicit;
  cert_info->cert_issue_perms[0].subject_perms.u.exp.num = 1;
  for (unsigned int i = 0; i < cert_info->cert_issue_perms[0].subject_perms.u.exp.num; i++) {
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].psid = 10 + i;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range_present = true;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.type = kDot2CertSspRangeType_Opaque;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp_num = 1;
    for (unsigned int j = 0; j < cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp_num; j++) {
      cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp[j].len = 31;
      for (unsigned int k = 0; k < cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp[j].len; k++) {
        cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.opaque.ssp[j].ssp[k] = k % 10;
      }
    }
  }
  cert_info->cert_issue_perms[0].min_chain_depth = 1;
  cert_info->cert_issue_perms[0].chain_depth_range = -1;
  cert_info->cert_issue_perms[0].ee_type.app = true;
  cert_info->cert_issue_perms[0].ee_type.enrol = true;
}


/**
 * @brief 최소길이(kDot2CertBitmapSspValueLen_Min=1/kDot2CertBitmapSspBitmaskLen_Min=1)
 *        bitmapSspRange sspValue/sspBitmask를 포함한 explicit 형식 certIssuePermissions를 포함한 인증서 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * ica 인증서의 내용을 임의로 조작한 g_shortest_bitmap_ssp_range_explicit_cert_issue_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleShortestBitmapSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleCertIssuePermissionsCertInfo(cert_info);
  cert_info->cert_issue_perms_num = 1;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_Explicit;
  cert_info->cert_issue_perms[0].subject_perms.u.exp.num = 1;
  for (unsigned int i = 0; i < cert_info->cert_issue_perms[0].subject_perms.u.exp.num; i++) {
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].psid = 10 + i;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range_present = true;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.type = kDot2CertSspRangeType_BitmapSspRange;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_value_len = 1;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_value[0] = 0x00;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_bitmask_len = 1;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_bitmask[0] = 0x10;
  }
  cert_info->cert_issue_perms[0].min_chain_depth = 1;
  cert_info->cert_issue_perms[0].chain_depth_range = -1;
  cert_info->cert_issue_perms[0].ee_type.app = true;
  cert_info->cert_issue_perms[0].ee_type.enrol = true;
}


/**
 * @brief 최대길이(kDot2CertBitmapSspValueLen_Max=32/kDot2CertBitmapSspBitmaskLen_Max=32)
 *        bitmapSspRange sspValue/sspBitmask를 포함한 explicit 형식 certIssuePermissions를 포함한 인증서 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * ica 인증서의 내용을 임의로 조작한 g_shortest_bitmap_ssp_range_explicit_cert_issue_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleLongestBitmapSspRangeExplicitCertIssuePermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleCertIssuePermissionsCertInfo(cert_info);
  cert_info->cert_issue_perms_num = 1;
  cert_info->cert_issue_perms[0].subject_perms.type = kDot2CertSubjectPermissionsType_Explicit;
  cert_info->cert_issue_perms[0].subject_perms.u.exp.num = 1;
  for (unsigned int i = 0; i < cert_info->cert_issue_perms[0].subject_perms.u.exp.num; i++) {
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].psid = 10 + i;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range_present = true;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.type = kDot2CertSspRangeType_BitmapSspRange;
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_value_len = 32;
    for (unsigned int j = 0; j < cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_value_len; j++) {
      cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_value[j] = j % 10;
    }
    cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_bitmask_len = 32;
    for (unsigned int j = 0; j < cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_bitmask_len; j++) {
      cert_info->cert_issue_perms[0].subject_perms.u.exp.psid_ssp_range[i].ssp_range.u.bitmap_ssp_range.ssp_bitmask[j] = (j % 10) + 0x10;
    }
  }
  cert_info->cert_issue_perms[0].min_chain_depth = 1;
  cert_info->cert_issue_perms[0].chain_depth_range = -1;
  cert_info->cert_issue_perms[0].ee_type.app = true;
  cert_info->cert_issue_perms[0].ee_type.enrol = true;
}


/**
 * @brief 최대개수(kDot2CertPermissionNum_Max=20) certRequestPermissions를 포함한 인증서 정보 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * ra 인증서의 내용을 임의로 조작한 g_max_cert_req_perms_cert 인증서에 해당됨.
 */
void Dot2Test_InitSampleMaxCertRequestPermissionsCertInfo(struct Dot2CertInfo *cert_info)
{
  Dot2Test_InitSampleRACertInfo(cert_info);
  cert_info->cert_req_perms_num = 20;
  for (unsigned int i = 0; i < cert_info->cert_req_perms_num; i++) {
    cert_info->cert_req_perms[i].subject_perms.type = kDot2CertSubjectPermissionsType_All;
    cert_info->cert_req_perms[i].min_chain_depth = 0;
    cert_info->cert_req_perms[i].chain_depth_range = 0;
    cert_info->cert_req_perms[i].ee_type.app = true;
    cert_info->cert_req_perms[i].ee_type.enrol = false;
  }
}
#endif
