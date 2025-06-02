/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 CMH 관련 공통함수 정의
  * @date 2021-12-30 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "test-common-funcs.h"


/**
 * @brief RSE용 CMHF들을 추가한다.
 */
void Dot2Test_AddRSECMHFs()
{
  /*
   * rse-0 ~ rse-4 인증서를 CMH 테이블에 추가한다.
   * 각 인증서에는 psid=135가 포함되어 있다
   * rse-0 유효기간(UTC): 2019-10-30 13:03:08 ~ 2019-12-04 23:03:08
   * rse-1 유효기간(UTC): 2019-12-04 23:03:08 ~ 2020-01-09 09:03:08
   * rse-2 유효기간(UTC): 2020-01-09 09:03:08 ~ 2020-02-13 19:03:08
   * rse-3 유효기간(UTC): 2020-02-13 19:03:08 ~ 2020-03-20 05:03:08
   * rse-4 유효기간(UTC): 2020-03-20 05:03:08 ~ 2020-04-24 15:03:08
   */
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_rse_0_cmhf, g_sample_rse_0_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_rse_1_cmhf, g_sample_rse_1_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_rse_2_cmhf, g_sample_rse_2_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_rse_3_cmhf, g_sample_rse_3_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_rse_4_cmhf, g_sample_rse_4_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 5U);
}


/**
 * @brief OBU용 CMHF들을 추가한다.
 */
void Dot2Test_AddOBUCMHFs()
{
  /*
   * obu-10a-0 ~ obu-10a-13 CMH(20개)를 CMH 테이블에 추가한다 -> 한 주 내에서 사용될 20개 CMH
   * obu-10b-0 ~ obu_10e-0 CMH(4개)를 CMH 테이블에 추가한다 -> 각 주 별로 1개씩 사용되는 CMH
   * 각 인증서에는 psid=32,38이 포함되어 있다.
   * obu-10a-x 유효기간(UTC): 2020-02-11 09:00:03 ~ 2020-02-18 10:00:03
   * obu-10b-0 유효기간(UTC): 2020-02-18 09:00:03 ~ 2020-02-25 10:00:03
   * obu-10c-0 유효기간(UTC): 2020-02-25 09:00:03 ~ 2020-03-03 10:00:03
   * obu-10d-0 유효기간(UTC): 2020-03-03 09:00:03 ~ 2020-03-10 10:00:03
   * obu-10e-0 유효기간(UTC): 2020-03-10 09:00:03 ~ 2020-03-17 10:00:03
   */
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_0_cmhf, g_sample_obu_10a_0_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_1_cmhf, g_sample_obu_10a_1_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_2_cmhf, g_sample_obu_10a_2_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_3_cmhf, g_sample_obu_10a_3_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_4_cmhf, g_sample_obu_10a_4_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_5_cmhf, g_sample_obu_10a_5_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_6_cmhf, g_sample_obu_10a_6_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_7_cmhf, g_sample_obu_10a_7_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_8_cmhf, g_sample_obu_10a_8_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_9_cmhf, g_sample_obu_10a_9_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_a_cmhf, g_sample_obu_10a_a_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_b_cmhf, g_sample_obu_10a_b_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_c_cmhf, g_sample_obu_10a_c_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_d_cmhf, g_sample_obu_10a_d_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_e_cmhf, g_sample_obu_10a_e_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_f_cmhf, g_sample_obu_10a_f_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_10_cmhf, g_sample_obu_10a_10_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_11_cmhf, g_sample_obu_10a_11_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_12_cmhf, g_sample_obu_10a_12_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10a_13_cmhf, g_sample_obu_10a_13_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10b_0_cmhf, g_sample_obu_10b_0_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10c_0_cmhf, g_sample_obu_10c_0_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10d_0_cmhf, g_sample_obu_10d_0_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(Dot2_LoadCMHF(g_sample_obu_10e_0_cmhf, g_sample_obu_10e_0_cmhf_size), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 5U);
}


#if 0
/**
 * @brief 샘플 RSE 0 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleRse0CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 1;
  cmh_info->psid[0] = 135;
  cmh_info->valid_start = 499525388 * 1000000ULL;
  cmh_info->valid_end = (499525388 + (3600 * 850)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Circular;
  cmh_info->valid_region.u.circular.center.lat = 374856150;
  cmh_info->valid_region.u.circular.center.lon = 1270392830;
  cmh_info->valid_region.u.circular.radius = 3000;

  memcpy(cmh_info->h, g_sample_rse_0_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_rse_0_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_rse_0_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_rse_0_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_rse_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_rse_0_cert_issuer_h8, 8);
}


/**
 * @brief 샘플 RSE 1 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleRse1CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 1;
  cmh_info->psid[0] = 135;
  cmh_info->valid_start = 502585388 * 1000000ULL;
  cmh_info->valid_end = (502585388 + (3600 * 850)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Circular;
  cmh_info->valid_region.u.circular.center.lat = 374856150;
  cmh_info->valid_region.u.circular.center.lon = 1270392830;
  cmh_info->valid_region.u.circular.radius = 3000;

  memcpy(cmh_info->h, g_sample_rse_1_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_rse_1_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_rse_1_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_rse_1_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_rse_1_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_rse_1_cert_issuer_h8, 8);
}


/**
 * @brief 샘플 RSE 2 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleRse2CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 1;
  cmh_info->psid[0] = 135;
  cmh_info->valid_start = 505645388 * 1000000ULL;
  cmh_info->valid_end = (505645388 + (3600 * 850)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Circular;
  cmh_info->valid_region.u.circular.center.lat = 374856150;
  cmh_info->valid_region.u.circular.center.lon = 1270392830;
  cmh_info->valid_region.u.circular.radius = 3000;

  memcpy(cmh_info->h, g_sample_rse_2_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_rse_2_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_rse_2_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_rse_2_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_rse_2_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_rse_2_cert_issuer_h8, 8);
}


/**
 * @brief 샘플 RSE 3 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleRse3CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 1;
  cmh_info->psid[0] = 135;
  cmh_info->valid_start = 508705388 * 1000000ULL;
  cmh_info->valid_end = (508705388 + (3600 * 850)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Circular;
  cmh_info->valid_region.u.circular.center.lat = 374856150;
  cmh_info->valid_region.u.circular.center.lon = 1270392830;
  cmh_info->valid_region.u.circular.radius = 3000;

  memcpy(cmh_info->h, g_sample_rse_3_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_rse_3_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_rse_3_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_rse_3_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_rse_3_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_rse_3_cert_issuer_h8, 8);
}


/**
 * @brief 샘플 RSE 4 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleRse4CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 1;
  cmh_info->psid[0] = 135;
  cmh_info->valid_start = 511765388 * 1000000ULL;
  cmh_info->valid_end = (511765388 + (3600 * 850)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Circular;
  cmh_info->valid_region.u.circular.center.lat = 374856150;
  cmh_info->valid_region.u.circular.center.lon = 1270392830;
  cmh_info->valid_region.u.circular.radius = 3000;

  memcpy(cmh_info->h, g_sample_rse_4_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_rse_4_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_rse_4_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_rse_4_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_rse_4_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_rse_4_cert_issuer_h8, 8);
}


/**
 * @brief 샘플 OBU 10A_0 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A0CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_0_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_0_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_0_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_0_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_0_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_1 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A1CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_1_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_1_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_1_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_1_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_1_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_1_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_2 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A2CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_2_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_2_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_2_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_2_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_2_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_2_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_a 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A3CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_3_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_3_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_3_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_3_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_3_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_3_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_4 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A4CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_4_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_4_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_4_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_4_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_4_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_4_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_5 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A5CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_5_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_5_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_5_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_5_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_5_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_5_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_6 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A6CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_6_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_6_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_6_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_6_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_6_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_6_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_7 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A7CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_7_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_7_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_7_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_7_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_7_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_7_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_8 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A8CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_8_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_8_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_8_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_8_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_8_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_8_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_9 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A9CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_9_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_9_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_9_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_9_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_9_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_9_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_a 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10AACMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_a_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_a_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_a_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_a_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_a_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_a_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_b 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10ABCMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_b_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_b_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_b_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_b_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_b_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_b_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_c 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10ACCMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_c_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_c_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_c_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_c_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_c_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_c_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_d 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10ADCMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_d_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_d_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_d_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_d_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_d_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_d_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_e 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10AECMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_e_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_e_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_e_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_e_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_e_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_e_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_f 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10AFCMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_f_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_f_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_f_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_f_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_f_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_f_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10A_10 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A10CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_10_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_10_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_10_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_10_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_10_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_10_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_11 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A11CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_11_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_11_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_11_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_11_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_11_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_11_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_12 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A12CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_12_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_12_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_12_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_12_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_12_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_12_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10a_13 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10A13CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 508496403 * 1000000ULL;
  cmh_info->valid_end = (508496403 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10a_13_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10a_13_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10a_13_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10a_13_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10a_13_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10a_13_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10b_0 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10B0CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 509101203 * 1000000ULL;
  cmh_info->valid_end = (509101203 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10b_0_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10b_0_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10b_0_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10b_0_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10b_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10b_0_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10c_0 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10C0CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 509706003 * 1000000ULL;
  cmh_info->valid_end = (509706003 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10c_0_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10c_0_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10c_0_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10c_0_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10c_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10c_0_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10d_0 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10D0CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 510310803 * 1000000ULL;
  cmh_info->valid_end = (510310803 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10d_0_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10d_0_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10d_0_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10d_0_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10d_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10d_0_cert_issuer_h8, 8);
}

/**
 * @brief 샘플 OBU 10e_0 인증서에 대한 CMH 정보를 설정한다.
 * @param[out] cmh_info CMH 정보가 저장될 정보구조체
 */
void Dot2Test_InitSampleObu10E0CMHInfo(struct Dot2CMHInfo *cmh_info)
{
  memset(cmh_info, 0, sizeof(struct Dot2CMHInfo));
  cmh_info->psid_num = 2;
  cmh_info->psid[0] = 32;
  cmh_info->psid[1] = 38;
  cmh_info->valid_start = 510915603 * 1000000ULL;
  cmh_info->valid_end = (510915603 + (3600 * 169)) * 1000000ULL;
  cmh_info->valid_region.present = true;
  cmh_info->valid_region.type = kDot2GeographicRegion_Identified;
  cmh_info->valid_region.u.identified.region_num = 2;
  cmh_info->valid_region.u.identified.region[0].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[0].u.country = 840;
  cmh_info->valid_region.u.identified.region[1].type = kDot2IdentifiedRegion_CountryOnly;
  cmh_info->valid_region.u.identified.region[1].u.country = 410;

  memcpy(cmh_info->h, g_sample_obu_10e_0_cert_h, DOT2_SHA_256_LEN);
  memcpy(cmh_info->h8, g_sample_obu_10e_0_cert_h8, 8);
  memcpy(cmh_info->h10, g_sample_obu_10e_0_cert_h10, 10);

  cmh_info->priv_key_type = kDot2PrivKey_Key;
  memcpy(cmh_info->key.priv_key.octets, g_sample_obu_10e_0_priv_key, DOT2_EC_256_KEY_LEN);
  memcpy(cmh_info->key.pub_key.u.octets, g_sample_obu_10e_0_cert_pub_key, DOT2_EC_256_PUB_KEY_LEN);

  memcpy(cmh_info->issuer_h8, g_sample_obu_10e_0_cert_issuer_h8, 8);
}
#endif
