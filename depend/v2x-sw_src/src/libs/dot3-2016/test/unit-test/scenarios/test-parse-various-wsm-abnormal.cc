/** 
 * @file
 * @brief 다양한 형태의 잘못된 WSM 파싱에 대한 단위테스트 구현 파일
 * @date 2020-08-01
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief 유효하지 않은 SubType 값을 갖는 WSM을 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(PARSE_VARIOUS_WSM_ABNORMAL, INVALID_SUBTYPE)
{
  extern uint8_t g_abnormal_wsm_with_invalid_subtype[];
  extern size_t g_abnormal_wsm_with_invalid_subtype_size;

  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size;
  uint8_t *payload;
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * WSM 파싱 시 정상적으로 예외처리하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_abnormal_wsm_with_invalid_subtype,
                          g_abnormal_wsm_with_invalid_subtype_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMPNHeaderSubType);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 Version 값을 갖는 WSM을 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(PARSE_VARIOUS_WSM_ABNORMAL, INVALID_VERSION)
{
  extern uint8_t g_abnormal_wsm_with_invalid_version[];
  extern size_t g_abnormal_wsm_with_invalid_version_size;

  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size;
  uint8_t *payload;
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * WSM 파싱 시 정상적으로 예외처리하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_abnormal_wsm_with_invalid_version,
                          g_abnormal_wsm_with_invalid_version_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMPNHeaderWSMPVersion);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 TPID 값을 갖는 WSM을 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(PARSE_VARIOUS_WSM_ABNORMAL, INVALID_TPID)
{
  extern uint8_t g_abnormal_wsm_with_invalid_tpid[];
  extern size_t g_abnormal_wsm_with_invalid_tpid_size;

  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size;
  uint8_t *payload;
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * WSM 파싱 시 정상적으로 예외처리하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_abnormal_wsm_with_invalid_tpid,
                          g_abnormal_wsm_with_invalid_tpid_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMPNHeaderTPID);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 PSID 값을 갖는 WSM을 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(PARSE_VARIOUS_WSM_ABNORMAL, INVALID_PSID)
{
  extern uint8_t g_abnormal_wsm_with_invalid_psid[];
  extern size_t g_abnormal_wsm_with_invalid_psid_size;

  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size;
  uint8_t *payload;
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * WSM 파싱 시 정상적으로 예외처리하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_abnormal_wsm_with_invalid_psid,
                          g_abnormal_wsm_with_invalid_psid_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidPSID);

  ReleaseTestEnv();
}


/**
 * @brief 너무 긴 페이로드를 갖는 WSM을 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(PARSE_VARIOUS_WSM_ABNORMAL, TOO_LONG_PAYLOAD)
{
  extern uint8_t g_abnormal_wsm_with_too_long_payload[];
  extern size_t g_abnormal_wsm_with_too_long_payload_size;

  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size;
  uint8_t *payload;
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * WSM 파싱 시 정상적으로 예외처리하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_abnormal_wsm_with_too_long_payload,
                          g_abnormal_wsm_with_too_long_payload_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMPayloadSize);

  ReleaseTestEnv();
}


/**
 * @brief 포함되면 안되는 확장필드(예: WSA ServiceInfo 등에 포함되는 확장필드)를 포함한 헤더를 갖는 WSM 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 *
 * asn.1 에 "ShortMsgNextTypes EXT-TYPE ::= {" 구문으로 들어갈 수 있는 확장필드가 제한되어 있어, asn.1 원문 자체를 바꾸지 않는 이상
 * 테스트벡터를 생성할 수 없다.
 * 따라서 본 테스트는 수행하지 않는다.
 */
TEST(PROCESS_VARIOUS_WSM_ABNORMAL, NOT_SUPPORTED_N_HEADER_EXTENSION)
{
}
