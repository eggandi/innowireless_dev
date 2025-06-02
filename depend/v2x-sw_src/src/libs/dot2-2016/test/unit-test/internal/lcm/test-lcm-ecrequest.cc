/** 
  * @file 
  * @brief 등록인증서 발급요청문 생성 기능에 대한 단위 테스트
  * @date 2022-05-01 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-vectors/test-vectors.h"
#include "../../test-common-funcs/test-common-funcs.h"


/**
 * @brief 등록인증서 발급요청문 생성 기능이 정상적으로 동작하는 것을 확인한다.
 */
TEST(CONSTRUCT_ECREQUEST, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t ecreq_1[kDot2SPDUSize_Max], ecreq_2[kDot2SPDUSize_Max], ecreq_3[kDot2SPDUSize_Max];
  struct Dot2ECKeyPair tmp_key_pair_1, tmp_key_pair_2, tmp_key_pair_3;
  struct Dot2ECRequestConstructParams params;
  struct Dot2ECRequestConstructResult res;
  memset(&params, 0, sizeof(params));
  int ret;

  /*
   * 준비 - 기대값 설정
   */
  {
    // 테스트벡터 ECRequest 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_1, ecreq_1), (int)g_tv_ecreq_size_1);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_2, ecreq_2), (int)g_tv_ecreq_size_2);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_3, ecreq_3), (int)g_tv_ecreq_size_3);

    // 임시 개인키/공개키 키쌍 정보
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_init_priv_key_1, tmp_key_pair_1.octs.priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_init_pub_key_1, tmp_key_pair_1.octs.pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    tmp_key_pair_1.eck = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&(tmp_key_pair_1.octs.priv_key), &ret);
    ASSERT_TRUE(tmp_key_pair_1.eck != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_init_priv_key_2, tmp_key_pair_2.octs.priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_init_pub_key_2, tmp_key_pair_2.octs.pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    tmp_key_pair_2.eck = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&(tmp_key_pair_2.octs.priv_key), &ret);
    ASSERT_TRUE(tmp_key_pair_2.eck != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_init_priv_key_3, tmp_key_pair_3.octs.priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_ecreq_init_pub_key_3, tmp_key_pair_3.octs.pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    tmp_key_pair_3.eck = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&(tmp_key_pair_3.octs.priv_key), &ret);
    ASSERT_TRUE(tmp_key_pair_3.eck != nullptr);
    ASSERT_EQ(ret, kDot2Result_Success);
  }

  /*
   * 테스트 - ECRequest #1가 정상적으로 생성되는 것을 확인한다.
   */
  {
    // 정상적으로 생성되는 것을 확인
    params.time = 581219273;
    params.valid_period.start = 581219273;
    params.valid_period.duration.type = kDot2CertDurationType_Years;
    params.valid_period.duration.duration = 6;
    params.valid_region.region_num = 1;
    params.valid_region.region[0] = 410;
    params.permissions.num = 3;
    params.permissions.psid[0] = 32;
    params.permissions.psid[1] = 35;
    params.permissions.psid[2] = 135;
    dot2_ConstructECRequest(&params, &tmp_key_pair_1, &res);
    ASSERT_EQ(res.ret, (int)g_tv_ecreq_size_1);
    ASSERT_TRUE(res.ec_req != nullptr);

    // 생성된 ECRequest 메시지가 기대값과 동일한지 확인 (서명은 랜덤하게 생성되므로 제외)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ec_req, ecreq_1, g_tv_ecreq_size_1 - 65));

    // 반환된 H8(발급요청문)과, 반환된 발급요청문에 대해 직접 계산한 H8값이 동일한지 확인
    uint8_t ecreq_h[DOT2_SHA_256_LEN];
    SHA256(res.ec_req, res.ret, ecreq_h);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ec_req_h8, DOT2_GET_SHA256_H8(ecreq_h), 8));

    // 반환된 임시개인키가 기대값과 동일한지 확인
    ASSERT_TRUE(Dot2Test_CompareOctets(res.init_priv_key.octs, tmp_key_pair_1.octs.priv_key.octs, DOT2_EC_256_KEY_LEN));

    free(res.ec_req);
  }

  /*
   * 테스트 - ECRequest #2가 정상적으로 생성되는 것을 확인한다.
   */
  {
    // 정상적으로 생성되는 것을 확인
    params.time = 581230081;
    params.valid_period.start = 581230081;
    params.valid_period.duration.type = kDot2CertDurationType_Years;
    params.valid_period.duration.duration = 6;
    params.valid_region.region_num = 1;
    params.valid_region.region[0] = 410;
    params.permissions.num = 3;
    params.permissions.psid[0] = 32;
    params.permissions.psid[1] = 35;
    params.permissions.psid[2] = 135;
    dot2_ConstructECRequest(&params, &tmp_key_pair_2, &res);
    ASSERT_EQ(res.ret, (int)g_tv_ecreq_size_2);
    ASSERT_TRUE(res.ec_req != nullptr);

    // 생성된 ECRequest 메시지가 기대값과 동일한지 확인 (서명은 랜덤하게 생성되므로 제외)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ec_req, ecreq_2, g_tv_ecreq_size_2 - 65));

    // 반환된 H8(발급요청문)과, 반환된 발급요청문에 대해 직접 계산한 H8값이 동일한지 확인
    uint8_t ecreq_h[DOT2_SHA_256_LEN];
    SHA256(res.ec_req, res.ret, ecreq_h);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ec_req_h8, DOT2_GET_SHA256_H8(ecreq_h), 8));

    // 반환된 임시개인키가 기대값과 동일한지 확인
    ASSERT_TRUE(Dot2Test_CompareOctets(res.init_priv_key.octs, tmp_key_pair_2.octs.priv_key.octs, DOT2_EC_256_KEY_LEN));

    free(res.ec_req);
  }

  /*
   * 테스트 - ECRequest #3가 정상적으로 생성되는 것을 확인한다.
   */
  {
    // 정상적으로 생성되는 것을 확인
    params.time = 581227071;
    params.valid_period.start = 581227071;
    params.valid_period.duration.type = kDot2CertDurationType_Years;
    params.valid_period.duration.duration = 6;
    params.valid_region.region_num = 1;
    params.valid_region.region[0] = 410;
    params.permissions.num = 3;
    params.permissions.psid[0] = 32;
    params.permissions.psid[1] = 35;
    params.permissions.psid[2] = 135;
    dot2_ConstructECRequest(&params, &tmp_key_pair_3, &res);
    ASSERT_EQ(res.ret, (int)g_tv_ecreq_size_3);
    ASSERT_TRUE(res.ec_req != nullptr);

    // 생성된 ECRequest 메시지가 기대값과 동일한지 확인 (서명은 랜덤하게 생성되므로 제외)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ec_req, ecreq_3, g_tv_ecreq_size_3 - 65));

    // 반환된 H8(발급요청문)과, 반환된 발급요청문에 대해 직접 계산한 H8값이 동일한지 확인
    uint8_t ecreq_h[DOT2_SHA_256_LEN];
    SHA256(res.ec_req, res.ret, ecreq_h);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ec_req_h8, DOT2_GET_SHA256_H8(ecreq_h), 8));

    // 반환된 임시개인키가 기대값과 동일한지 확인
    ASSERT_TRUE(Dot2Test_CompareOctets(res.init_priv_key.octs, tmp_key_pair_3.octs.priv_key.octs, DOT2_EC_256_KEY_LEN));

    free(res.ec_req);
  }

  Dot2_Release();
}
