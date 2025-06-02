/** 
 * @file
 * @brief Dot3_ParseWSM() API에 대한 단위테스트 구현 파일
 * @date 2020-07-20
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_ParseWSM() API 호출 시 필수정보를 포함한 WSM이 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ParseWSM, MANDATORY_PARAMS)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값을 설정한다.
   */
  for (size_t i = 0; i < sizeof(expected); i++) {
    expected[i] = (uint8_t)(i % 16);
  }

  /*
   * 필수필드만 포함하는 WSM이 정상적으로 파싱되는 것을 확인한다.
   */
  expected_size = 1400 - (kDot3WSMHdrSize_Min + 1);
  payload = Dot3_ParseWSM(g_1400_bytes_wsm_with_no_ext_hdr,
                          g_1400_bytes_wsm_with_no_ext_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.transmit_power, kDot3Power_NA);
  ASSERT_EQ(params.psid, kDot3PSID_Min);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  free(payload);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSM() API 호출 시 옵션정보를 포함한 WSM이 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ParseWSM, OPTIONAL_PARAMS)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값을 설정한다.
   */
  for (size_t i = 0; i < sizeof(expected); i++) {
    expected[i] = (uint8_t)(i % 16);
  }

  /*
   * 모든 확장필드까지 포함하는 WSM이 정상적으로 파싱되는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  payload = Dot3_ParseWSM(g_1400_bytes_wsm_with_max_hdr,
                          g_1400_bytes_wsm_with_max_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.chan_num, 172UL);
  ASSERT_EQ(params.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.transmit_power, 30);
  ASSERT_EQ(params.psid, kDot3PSID_Max);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  free(payload);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSM() API 호출 시 NULL 파라미터가 전달될 때의 동작을 확인한다.
 */
TEST(Dot3_ParseWSM, CHECK_PARAMS_NULL)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * wsm 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(NULL,
                          g_min_size_wsm_with_max_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * params 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_min_size_wsm_with_max_hdr,
                          g_min_size_wsm_with_max_hdr_size,
                          NULL,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * payload_size 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_min_size_wsm_with_max_hdr,
                          g_min_size_wsm_with_max_hdr_size,
                          &params,
                          NULL,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * wsr_registered 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_min_size_wsm_with_max_hdr,
                          g_min_size_wsm_with_max_hdr_size,
                          &params,
                          &payload_size,
                          NULL,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * ret 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_min_size_wsm_with_max_hdr,
                          g_min_size_wsm_with_max_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          NULL);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSM() API 호출 시 전달되는 wsm_size 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ParseWSM, CHECK_PARAM_WSM_SIZE)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값을 설정한다.
   */
  for (size_t i = 0; i < sizeof(expected); i++) {
    expected[i] = (uint8_t)(i % 16);
  }

  /*
   * 최소길이보다 작은 값을 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_min_size_wsm_with_max_hdr,
                          kDot3WSMSize_Min - 1,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMSize);

  /*
   * 최소길이 WSM을 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = 0;
  payload = Dot3_ParseWSM(g_min_size_wsm_with_no_ext_hdr,
                          g_min_size_wsm_with_no_ext_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.psid, 0UL);
  ASSERT_EQ(params.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.transmit_power, kDot3Power_NA);
  ASSERT_EQ(payload_size, expected_size);

  /*
   * 최대길이 WSM을 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = kDot3WSMSize_Max - kDot3WSMHdrSize_Max;
  payload = Dot3_ParseWSM(g_max_size_wsm_with_max_hdr,
                          g_max_size_wsm_with_max_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.psid, kDot3PSID_Max);
  ASSERT_EQ(params.chan_num, 172UL);
  ASSERT_EQ(params.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.transmit_power, 30);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  free(payload);

  /*
   * 최대길이보다 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSM(g_min_size_wsm_with_max_hdr,
                          kDot3WSMSize_Max + 1,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMSize);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSM() API 호출 시 WSR 등록 여부에 따른 wsr_registered 파라미터의 반환값을 확인한다.
 */
TEST(Dot3_ParseWSM, CHECK_PARAM_WSR_REGISTERED)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값을 설정한다.
   */
  for (size_t i = 0; i < sizeof(expected); i++) {
    expected[i] = (uint8_t)(i % 16);
  }

  /*
   * 등록되지 않은 PSID에 대한 WSM을 파싱하면 wsr_registered 파라미터가 false로 반환되는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  payload = Dot3_ParseWSM(g_1400_bytes_wsm_with_max_hdr,
                          g_1400_bytes_wsm_with_max_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.chan_num, 172UL);
  ASSERT_EQ(params.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.transmit_power, 30);
  ASSERT_EQ(params.psid, kDot3PSID_Max);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  ASSERT_FALSE(wsr_registered);
  free(payload);

  /*
   * PSID를 등록한다.
   */
  ASSERT_EQ(Dot3_AddWSR(kDot3PSID_Max), 1);

  /*
   * 등록된 PSID에 대한 WSM을 파싱하면 wsr_registered 파라미터가 false로 반환되는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  payload = Dot3_ParseWSM(g_1400_bytes_wsm_with_max_hdr,
                          g_1400_bytes_wsm_with_max_hdr_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.chan_num, 172UL);
  ASSERT_EQ(params.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.transmit_power, 30);
  ASSERT_EQ(params.psid, kDot3PSID_Max);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  ASSERT_TRUE(wsr_registered);
  free(payload);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSM() API 호출 시 전달되는 WSM 내 PSID 값에 따른 동작을 확인한다.
 */
TEST(Dot3_ParseWSM, CHECK_PSID)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3WSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 1바이트 길이 PSID를 담은 WSM을 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = 0;
  payload = Dot3_ParseWSM(g_min_size_wsm_with_1byte_psid,
                          g_min_size_wsm_with_1byte_psid_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.psid, 0UL);
  ASSERT_EQ(params.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.transmit_power, kDot3Power_NA);
  ASSERT_EQ(payload_size, expected_size);

  /*
   * 2바이트 길이 PSID를 담은 WSM을 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = 0;
  payload = Dot3_ParseWSM(g_min_size_wsm_with_2bytes_psid,
                          g_min_size_wsm_with_2bytes_psid_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.psid, 128UL);
  ASSERT_EQ(params.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.transmit_power, kDot3Power_NA);
  ASSERT_EQ(payload_size, expected_size);

  /*
   * 3바이트 길이 PSID를 담은 WSM을 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = 0;
  payload = Dot3_ParseWSM(g_min_size_wsm_with_3bytes_psid,
                          g_min_size_wsm_with_3bytes_psid_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.psid, 16512UL);
  ASSERT_EQ(params.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.transmit_power, kDot3Power_NA);
  ASSERT_EQ(payload_size, expected_size);

  /*
   * 4바이트 길이 PSID를 담은 WSM을 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = 0;
  payload = Dot3_ParseWSM(g_min_size_wsm_with_4bytes_psid,
                          g_min_size_wsm_with_4bytes_psid_size,
                          &params,
                          &payload_size,
                          &wsr_registered,
                          &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.psid, 2113664UL);
  ASSERT_EQ(params.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.transmit_power, kDot3Power_NA);
  ASSERT_EQ(payload_size, expected_size);

  ReleaseTestEnv();
}

