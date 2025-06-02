/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 OBU 인증서 관련 공통함수 정의
  * @date 2022-01-04 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "test-common-funcs.h"

#if 0

/**
 * @brief 샘플 obu-10a-0 인증서(g_sample_obu_10a_0_cert) 정보를 설정한다.
 * @param[out] cert_info 인증서정보가 저장될 정보구조체
 *
 * trusted와 verified는 상황에 따라 달라지기 때문에 여기서 설정할 수 없다.
 */
void Dot2Test_InitSampleObu10A0CertInfo(struct Dot2CertInfo *cert_info)
{
  memset(cert_info, 0, sizeof(struct Dot2CertInfo));
  cert_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cert_info->issuer.hashedid8, g_sample_obu_10a_0_cert_issuer_h8, 8);
  cert_info->valid_start = 508496403 * 1000000ULL;
  cert_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;;
  cert_info->valid_region.present = true;
  cert_info->valid_region.type = kDot2GeographicRegion_Identified;
  cert_info->valid_region.u.identified.region_num = 2;
  cert_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[0].u.country = 840;
  cert_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cert_info->valid_region.u.identified.region[1].u.country = 410;
  cert_info->app_perms_num = 2;
  cert_info->app_perms[0].psid = 32;
  cert_info->app_perms[0].ssp_present = false;
  cert_info->app_perms[1].psid = 38;
  cert_info->app_perms[1].ssp_present = false;
  cert_info->cert_issue_perms_num = 0;
  cert_info->cert_req_perms_num = 0;
  cert_info->verify_key.type = kDot2CertVerificationKeyIndicatorType_ReconstructValue;
  memcpy(cert_info->verify_key.u.recon_pub.u.octets, g_sample_obu_10a_0_cert_reconstruct_value, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  cert_info->signature.present = false;
  memcpy(cert_info->h, g_sample_obu_10a_0_cert_h, 32);
  memcpy(cert_info->h8, g_sample_obu_10a_0_cert_h8, 8);
  memcpy(cert_info->h10, g_sample_obu_10a_0_cert_h10, 10);
  memcpy(cert_info->verify_pub_key_pair.pub_key.u.octets, g_sample_obu_10a_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);
}
#endif
