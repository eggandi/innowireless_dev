/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 SCC 인증서 관련 공통함수 정의
  * @date 2022-07-02 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <cstring>

// 라이브러리 내부 헤더 파일
#include "certificate/cert-info/dot2-scc-cert-info.h"

// 테스트 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "../test-common-funcs/test-common-funcs.h"


/**
 * @brief 테스트벡터 RCA 인증서컨텐츠를 설정한다. g_tv_rca_cert 인증서에 해당됨
 * @param[out] contents 인증서컨텐츠가 저장될 정보구조체
 */
void Dot2Test_InitTestVector_RCACertContents(struct Dot2SCCCertContents *contents)
{
  memset(contents, 0, sizeof(struct Dot2SCCCertContents));
  contents->type = kDot2SCCCertType_RCA;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_pub_key_uncomp, contents->verify_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  contents->common.type = g_tv_rca_cert_type;
  contents->common.issuer.type = g_tv_rca_cert_issuer_id_type;
  contents->common.id.type = g_tv_rca_cert_id_type;
  contents->common.id.u.name.len = strlen(g_tv_rca_cert_id_name);
  contents->common.id.u.name.name = (char *)calloc(1, contents->common.id.u.name.len + 1);
  strncpy(contents->common.id.u.name.name, g_tv_rca_cert_id_name, contents->common.id.u.name.len);
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_craca_id, contents->common.craca_id), 3);
  contents->common.crl_series = g_tv_rca_cert_crl_series;
  contents->common.valid_start = g_tv_rca_cert_valid_start;
  contents->common.valid_end = g_tv_rca_cert_valid_end;
  contents->common.valid_region.type = g_tv_rca_cert_valid_region_type;
  contents->common.verify_key_indicator.type = g_tv_rca_cert_key_indicator_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_key_indicator, contents->common.verify_key_indicator.key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  contents->common.enc_pub_key_present = g_tv_rca_cert_enc_pub_key_present;
}


/**
 * @brief 테스트벡터 ICA 인증서컨텐츠를 설정한다. g_tv_ica_cert 인증서에 해당됨
 * @param[out] contents 인증서컨텐츠가 저장될 정보구조체
 */
void Dot2Test_InitTestVector_ICACertContents(struct Dot2SCCCertContents *contents)
{
  memset(contents, 0, sizeof(struct Dot2SCCCertContents));
  contents->type = kDot2SCCCertType_ICA;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_pub_key_uncomp, contents->verify_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  contents->common.type = g_tv_ica_cert_type;
  contents->common.issuer.type = g_tv_ica_cert_issuer_id_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_issuer_h8, contents->common.issuer.h8), 8);
  contents->common.id.type = g_tv_ica_cert_id_type;
  contents->common.id.u.name.len = strlen(g_tv_ica_cert_id_name);
  contents->common.id.u.name.name = (char *)calloc(1, contents->common.id.u.name.len + 1);
  strncpy(contents->common.id.u.name.name, g_tv_ica_cert_id_name, contents->common.id.u.name.len);
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_craca_id, contents->common.craca_id), 3);
  contents->common.crl_series = g_tv_ica_cert_crl_series;
  contents->common.valid_start = g_tv_ica_cert_valid_start;
  contents->common.valid_end = g_tv_ica_cert_valid_end;
  contents->common.valid_region.type = g_tv_ica_cert_valid_region_type;
  contents->common.valid_region.u.id.num = g_tv_ica_cert_valid_region_num;
  for (unsigned int i = 0; i < g_tv_ica_cert_valid_region_num; i++) {
    contents->common.valid_region.u.id.country[i] = g_tv_ica_cert_valid_region[i];
  }
  contents->common.verify_key_indicator.type = g_tv_ica_cert_key_indicator_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_key_indicator, contents->common.verify_key_indicator.key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  contents->common.enc_pub_key_present = g_tv_ica_cert_enc_pub_key_present;
}


/**
 * @brief 테스트벡터 PCA 인증서컨텐츠를 설정한다. g_tv_pca_cert 인증서에 해당됨
 * @param[out] info contents 인증서컨텐츠가 저장될 정보구조체
 */
void Dot2Test_InitTestVector_PCACertContents(struct Dot2SCCCertContents *contents)
{
  memset(contents, 0, sizeof(struct Dot2SCCCertContents));
  contents->type = kDot2SCCCertType_PCA;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_pub_key_uncomp, contents->verify_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  contents->common.type = g_tv_pca_cert_type;
  contents->common.issuer.type = g_tv_pca_cert_issuer_id_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_issuer_h8, contents->common.issuer.h8), 8);
  contents->common.id.type = g_tv_pca_cert_id_type;
  contents->common.id.u.name.len = strlen(g_tv_pca_cert_id_name);
  contents->common.id.u.name.name = (char *)calloc(1, contents->common.id.u.name.len + 1);
  strncpy(contents->common.id.u.name.name, g_tv_pca_cert_id_name, contents->common.id.u.name.len);
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_craca_id, contents->common.craca_id), 3);
  contents->common.crl_series = g_tv_pca_cert_crl_series;
  contents->common.valid_start = g_tv_pca_cert_valid_start;
  contents->common.valid_end = g_tv_pca_cert_valid_end;
  contents->common.valid_region.type = g_tv_pca_cert_valid_region_type;
  contents->common.valid_region.u.id.num = g_tv_pca_cert_valid_region_num;
  for (unsigned int i = 0; i < g_tv_pca_cert_valid_region_num; i++) {
    contents->common.valid_region.u.id.country[i] = g_tv_pca_cert_valid_region[i];
  }
  contents->common.verify_key_indicator.type = g_tv_pca_cert_key_indicator_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_key_indicator, contents->common.verify_key_indicator.key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  contents->common.enc_pub_key_present = g_tv_pca_cert_enc_pub_key_present;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_enc_pub_key_uncomp, contents->common.enc_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 테스트벡터 ECA 인증서컨텐츠를 설정한다. g_tv_eca_cert 인증서에 해당됨
 * @param[out] info contents 인증서컨텐츠가 저장될 정보구조체
 */
void Dot2Test_InitTestVector_ECACertContents(struct Dot2SCCCertContents *contents)
{
  memset(contents, 0, sizeof(struct Dot2SCCCertContents));
  contents->type = kDot2SCCCertType_ECA;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_pub_key_uncomp, contents->verify_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  contents->common.type = g_tv_eca_cert_type;
  contents->common.issuer.type = g_tv_eca_cert_issuer_id_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_issuer_h8, contents->common.issuer.h8), 8);
  contents->common.id.type = g_tv_eca_cert_id_type;
  contents->common.id.u.name.len = strlen(g_tv_eca_cert_id_name);
  contents->common.id.u.name.name = (char *)calloc(1, contents->common.id.u.name.len + 1);
  strncpy(contents->common.id.u.name.name, g_tv_eca_cert_id_name, contents->common.id.u.name.len);
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_craca_id, contents->common.craca_id), 3);
  contents->common.crl_series = g_tv_eca_cert_crl_series;
  contents->common.valid_start = g_tv_eca_cert_valid_start;
  contents->common.valid_end = g_tv_eca_cert_valid_end;
  contents->common.valid_region.type = g_tv_eca_cert_valid_region_type;
  contents->common.valid_region.u.id.num = g_tv_eca_cert_valid_region_num;
  for (unsigned int i = 0; i < g_tv_eca_cert_valid_region_num; i++) {
    contents->common.valid_region.u.id.country[i] = g_tv_eca_cert_valid_region[i];
  }
  contents->common.verify_key_indicator.type = g_tv_eca_cert_key_indicator_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_key_indicator, contents->common.verify_key_indicator.key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  contents->common.enc_pub_key_present = g_tv_eca_cert_enc_pub_key_present;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_enc_pub_key_uncomp, contents->common.enc_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
}


/**
 * @brief 테스트벡터 RA 인증서컨텐츠를 설정한다. g_tv_ra_cert 인증서에 해당됨
 * @param[out] info contents 인증서컨텐츠가 저장될 정보구조체
 */
void Dot2Test_InitTestVector_RACertContents(struct Dot2SCCCertContents *contents)
{
  memset(contents, 0, sizeof(struct Dot2SCCCertContents));
  contents->type = kDot2SCCCertType_RA;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_pub_key_uncomp, contents->verify_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
  contents->common.type = g_tv_ra_cert_type;
  contents->common.issuer.type = g_tv_ra_cert_issuer_id_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_issuer_h8, contents->common.issuer.h8), 8);
  contents->common.id.type = g_tv_ra_cert_id_type;
  contents->common.id.u.name.len = strlen(g_tv_ra_cert_id_name);
  contents->common.id.u.name.name = (char *)calloc(1, contents->common.id.u.name.len + 1);
  strncpy(contents->common.id.u.name.name, g_tv_ra_cert_id_name, contents->common.id.u.name.len);
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_craca_id, contents->common.craca_id), 3);
  contents->common.crl_series = g_tv_ra_cert_crl_series;
  contents->common.valid_start = g_tv_ra_cert_valid_start;
  contents->common.valid_end = g_tv_ra_cert_valid_end;
  contents->common.valid_region.type = g_tv_ra_cert_valid_region_type;
  contents->common.valid_region.u.id.num = g_tv_ra_cert_valid_region_num;
  for (unsigned int i = 0; i < g_tv_ra_cert_valid_region_num; i++) {
    contents->common.valid_region.u.id.country[i] = g_tv_ra_cert_valid_region[i];
  }
  contents->common.verify_key_indicator.type = g_tv_ra_cert_key_indicator_type;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_key_indicator, contents->common.verify_key_indicator.key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);
  contents->common.enc_pub_key_present = g_tv_ra_cert_enc_pub_key_present;
  ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_enc_pub_key_uncomp, contents->common.enc_pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
}
