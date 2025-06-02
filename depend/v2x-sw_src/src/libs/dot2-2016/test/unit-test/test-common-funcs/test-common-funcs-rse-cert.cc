/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 RSE 인증서 관련 공통함수 정의
  * @date 2022-01-04 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cert-info/dot2-cert-info-inline.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "test-common-funcs.h"


/**
 * @brief 샘플 rse-0 인증서(g_sample_rse_0_cert) 정보를 설정한다.
 * @param[out] entry 인증서정보가 저장될 정보구조체
 *
 * trusted와 verified는 상황에 따라 달라지기 때문에 여기서 설정할 수 없다.
 */
void Dot2Test_InitSampleRse0CertInfo(struct Dot2EECertCacheEntry *entry)
{
  memset(entry, 0, sizeof(struct Dot2SCCCertInfoEntry));
  entry->contents.common.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(entry->contents.common.issuer.h8, g_sample_rse_0_cert_issuer_h8, 8);
  entry->contents.common.valid_start = 499525388 * 1000000ULL;
  entry->contents.common.valid_end = (499525388 + (3600 * 850)) * 1000000ULL;
  entry->contents.common.valid_region.type = kDot2CertValidRegionType_Circular;
  entry->contents.common.valid_region.u.circular.center.lat = 374856150;
  entry->contents.common.valid_region.u.circular.center.lon = 1270392830;
  entry->contents.common.valid_region.u.circular.radius = 3000;
  entry->contents.app_perms.psid_num = 1;
  entry->contents.app_perms.psid[0] = 135;
  entry->contents.common.verify_key_indicator.type = kDot2CertVerificationKeyIndicatorType_ReconstructValue;
  memcpy(entry->contents.common.verify_key_indicator.key.u.octs, g_sample_rse_0_cert_reconstruct_value, DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  memcpy(entry->cert_h.octs, g_sample_rse_0_cert_h, 32);
  memcpy(entry->contents.verify_pub_key.u.octs, g_sample_rse_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 수신메시지로부터 추출된 application 인증서가 인증서정보테이블에 정상적으로 추가된 것을 확인한다.
 * @param[in] verified 해당 인증서정보의 verified 상태여부 (테스트케이스별로 시나리오에 따라 값을 설정한다)
 *
 * 본 테스트에서 사용된 인증서는 g_sample_rse_0_cert이다.
 */
void Dot2Test_CheckRegisteredRSE0AppCert(bool verified)
{
  struct Dot2SCCCertInfoEntry *pca_entry = dot2_FindSCCCertWithHashedID8(g_sample_pca_cert_h8);
  ASSERT_TRUE(pca_entry != nullptr);

  // 비교를 위한 샘플 정보 설정
  struct Dot2EECertCacheEntry sample;
  Dot2Test_InitSampleRse0CertInfo(&sample);
  sample.revoked = false;
  // 테이블에 추가된 것을 확인
  struct Dot2EECertCacheEntry *entry = dot2_FindEECertCacheWithH8(g_sample_rse_0_cert_h8);
  ASSERT_TRUE(entry != nullptr);
  // 인증서데이터 정상 등록 확인
  ASSERT_EQ(entry->cert_size, g_sample_rse_0_cert_size);
  ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert, g_sample_rse_0_cert, entry->cert_size));
  // 상위인증서 참조 정상 등록 확인
  ASSERT_TRUE(entry->issuer == pca_entry);
  ASSERT_EQ(entry->issuer->cert_size, g_sample_pca_cert_size);
  ASSERT_TRUE(Dot2Test_CompareOctets(entry->issuer->cert, g_sample_pca_cert, entry->issuer->cert_size));
  // 인증서정보 정상 저장 확인
  ASSERT_EQ(entry->contents.common.issuer.type, sample.contents.common.issuer.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(entry->contents.common.issuer.h8, sample.contents.common.issuer.h8, 8));
  ASSERT_EQ(entry->contents.common.valid_start, sample.contents.common.valid_start);
  ASSERT_EQ(entry->contents.common.valid_end, sample.contents.common.valid_end);
  ASSERT_EQ(entry->contents.common.valid_region.type, sample.contents.common.valid_region.type);
  ASSERT_EQ(entry->contents.common.valid_region.u.circular.center.lat, sample.contents.common.valid_region.u.circular.center.lat);
  ASSERT_EQ(entry->contents.common.valid_region.u.circular.center.lon, sample.contents.common.valid_region.u.circular.center.lon);
  ASSERT_EQ(entry->contents.common.valid_region.u.circular.radius, sample.contents.common.valid_region.u.circular.radius);
  ASSERT_EQ(entry->contents.app_perms.psid_num, sample.contents.app_perms.psid_num);
  ASSERT_EQ(entry->contents.app_perms.psid[0], sample.contents.app_perms.psid[0]);
  ASSERT_EQ(entry->contents.common.verify_key_indicator.type, sample.contents.common.verify_key_indicator.type);
  ASSERT_TRUE(Dot2Test_CompareOctets(entry->contents.common.verify_key_indicator.key.u.octs, sample.contents.common.verify_key_indicator.key.u.octs, DOT2_EC_256_PUB_KEY_LEN));
  ASSERT_TRUE(Dot2Test_CompareOctets(entry->cert_h.octs, sample.cert_h.octs, 32));
  ASSERT_TRUE(Dot2Test_CompareOctets(entry->contents.verify_pub_key.u.octs, sample.contents.verify_pub_key.u.octs, DOT2_EC_256_PUB_KEY_LEN));
}


/**
 * @brief Sample RSE-0 application 인증서가 인증서정보테이블에 저장되어 있지 않은 것을 확인한다.
 * 본 테스트에서 사용된 인증서는 g_sample_rse_0_cert이다.
 */
void Dot2Test_CheckNoRSE0AppCert()
{
  // 인증서정보테이블에 없는 것을 확인
  struct Dot2EECertCacheEntry *app_cert_entry = dot2_FindEECertCacheWithH8(g_sample_rse_0_cert_h8);
  ASSERT_TRUE(app_cert_entry == nullptr);
}
