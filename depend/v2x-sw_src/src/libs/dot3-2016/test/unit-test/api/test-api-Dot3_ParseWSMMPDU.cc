/** 
 * @file
 * @brief Dot3_ParseWSMMPDU() API에 대한 단위테스트 구현 파일
 * @date 2020-07-20
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_ParseWSMMPDU() API 호출 시 필수정보를 포함한 WSM MPDU가 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ParseWSMMPDU, MANDATORY_PARAMS)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3MACAndWSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값을 설정한다.
   */
  for (size_t i = 0; i < sizeof(expected); i++) {
    expected[i] = (uint8_t)(i % 16);
  }

  /*
   * 필수필드만 포함하는 WSM MPDU가 정상적으로 파싱되는 것을 확인한다.
   */
  expected_size = 1400 - (kDot3WSMHdrSize_Min + 1);
  payload = Dot3_ParseWSMMPDU(g_1400_bytes_wsm_mpdu_with_no_ext_hdr,
                              g_1400_bytes_wsm_mpdu_with_no_ext_hdr_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_TRUE(CompareBytes(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN));
  ASSERT_TRUE(CompareBytes(params.mac.src_mac_addr, g_my_addr, MAC_ALEN));
  ASSERT_EQ(params.mac.priority, 0UL);
  ASSERT_EQ(params.wsm.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.wsm.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.wsm.transmit_power, kDot3Power_NA);
  ASSERT_EQ(params.wsm.psid, kDot3PSID_Min);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  free(payload);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSMMPDU() API 호출 시 옵션정보를 포함한 WSM MPDU가 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ParseWSMMPDU, OPTIONAL_PARAMS)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3MACAndWSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값을 설정한다.
   */
  for (size_t i = 0; i < sizeof(expected); i++) {
    expected[i] = (uint8_t)(i % 16);
  }

  /*
   * 모든 확장필드까지 포함하는 WSM MPDU가 정상적으로 파싱되는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  payload = Dot3_ParseWSMMPDU(g_1400_bytes_wsm_mpdu_with_max_hdr,
                              g_1400_bytes_wsm_mpdu_with_max_hdr_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_TRUE(CompareBytes(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN));
  ASSERT_TRUE(CompareBytes(params.mac.src_mac_addr, g_my_addr, MAC_ALEN));
  ASSERT_EQ(params.mac.priority, 0UL);
  ASSERT_EQ(params.wsm.chan_num, 172UL);
  ASSERT_EQ(params.wsm.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.wsm.transmit_power, 30);
  ASSERT_EQ(params.wsm.psid, kDot3PSID_Max);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  free(payload);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSMMPDU() API 호출 시 NULL 파라미터가 전달될 때의 동작을 확인한다.
 */
TEST(Dot3_ParseWSMMPDU, CHECK_PARAMS_NULL)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3MACAndWSMParseParams params;
  memset(&params, 0, sizeof(params));

  /*
   * mpdu 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSMMPDU(NULL,
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
  payload = Dot3_ParseWSMMPDU(g_min_size_wsm_with_max_hdr,
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
  payload = Dot3_ParseWSMMPDU(g_min_size_wsm_with_max_hdr,
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
  payload = Dot3_ParseWSMMPDU(g_min_size_wsm_with_max_hdr,
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
  payload = Dot3_ParseWSMMPDU(g_min_size_wsm_with_max_hdr,
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
 * @brief Dot3_ParseWSMMPDU() API 호출 시 전달되는 mpdu_size 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ParseWSMMPDU, CHECK_PARAM_MPDU_SIZE)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3MACAndWSMParseParams params;
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
  payload = Dot3_ParseWSMMPDU(g_min_size_wsm_with_max_hdr,
                              kDot3MPDUSize_Min - 1,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidMPDUSize);

  /*
   * 최소길이 WSM MPDU를 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = 0;
  payload = Dot3_ParseWSMMPDU(g_min_size_wsm_mpdu_with_no_ext_hdr,
                              g_min_size_wsm_mpdu_with_no_ext_hdr_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_TRUE(CompareBytes(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN));
  ASSERT_TRUE(CompareBytes(params.mac.src_mac_addr, g_my_addr, MAC_ALEN));
  ASSERT_EQ(params.mac.priority, 0UL);
  ASSERT_EQ(params.wsm.psid, 0UL);
  ASSERT_EQ(params.wsm.chan_num, kDot3ChannelNumber_NA);
  ASSERT_EQ(params.wsm.datarate, kDot3DataRate_NA);
  ASSERT_EQ(params.wsm.transmit_power, kDot3Power_NA);
  ASSERT_EQ(payload_size, expected_size);

  /*
   * 최대길이 WSM MPDU를 전달하면 정상적으로 파싱하는 것을 확인한다.
   */
  expected_size = kDot3WSMSize_Max - kDot3WSMHdrSize_Max;
  payload = Dot3_ParseWSMMPDU(g_max_size_wsm_mpdu_with_max_hdr,
                              g_max_size_wsm_mpdu_with_max_hdr_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_TRUE(CompareBytes(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN));
  ASSERT_TRUE(CompareBytes(params.mac.src_mac_addr, g_my_addr, MAC_ALEN));
  ASSERT_EQ(params.mac.priority, 0UL);
  ASSERT_EQ(params.wsm.psid, kDot3PSID_Max);
  ASSERT_EQ(params.wsm.chan_num, 172UL);
  ASSERT_EQ(params.wsm.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.wsm.transmit_power, 30);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  free(payload);

  /*
   * 최대길이보다 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  payload = Dot3_ParseWSMMPDU(g_min_size_wsm_with_max_hdr,
                              kDot3MPDUSize_Max + 1,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidMPDUSize);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSMMPDU() API 호출 시 WSR 등록 여부에 따른 wsr_registered 파라미터의 반환값을 확인한다.
 */
TEST(Dot3_ParseWSMMPDU, CHECK_PARAM_WSR_REGISTERED)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3MACAndWSMParseParams params;
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
  payload = Dot3_ParseWSMMPDU(g_1400_bytes_wsm_mpdu_with_max_hdr,
                              g_1400_bytes_wsm_mpdu_with_max_hdr_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_TRUE(CompareBytes(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN));
  ASSERT_TRUE(CompareBytes(params.mac.src_mac_addr, g_my_addr, MAC_ALEN));
  ASSERT_EQ(params.mac.priority, 0UL);
  ASSERT_EQ(params.wsm.chan_num, 172UL);
  ASSERT_EQ(params.wsm.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.wsm.transmit_power, 30);
  ASSERT_EQ(params.wsm.psid, kDot3PSID_Max);
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
  payload = Dot3_ParseWSMMPDU(g_1400_bytes_wsm_mpdu_with_max_hdr,
                              g_1400_bytes_wsm_mpdu_with_max_hdr_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.wsm.chan_num, 172UL);
  ASSERT_TRUE(CompareBytes(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN));
  ASSERT_TRUE(CompareBytes(params.mac.src_mac_addr, g_my_addr, MAC_ALEN));
  ASSERT_EQ(params.mac.priority, 0UL);
  ASSERT_EQ(params.wsm.datarate, kDot3DataRate_6Mbps);
  ASSERT_EQ(params.wsm.transmit_power, 30);
  ASSERT_EQ(params.wsm.psid, kDot3PSID_Max);
  ASSERT_EQ(payload_size, expected_size);
  ASSERT_TRUE(CompareBytes(payload, expected, payload_size));
  ASSERT_TRUE(wsr_registered);
  free(payload);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSMMPDU() API 호출 시 전달되는 하위계층 헤더에 따른 동작을 확인한다.
 */
TEST(Dot3_ParseWSMMPDU, CHECK_LOWER_LAYER_HDR)
{
  InitTestEnv();

  int ret;
  Dot3WSMPayloadSize payload_size, expected_size;
  uint8_t *payload, expected[kDot3WSMPayloadSize_Max];
  bool wsr_registered;
  struct Dot3MACAndWSMParseParams params;
  memset(&params, 0, sizeof(params));
  uint8_t mpdu[kDot3MPDUSize_Max];
  Dot3MPDUSize mpdu_size;

  /*
   * 페이로드 기대값을 설정한다.
   */
  for (size_t i = 0; i < sizeof(expected); i++) {
    expected[i] = (uint8_t)(i % 16);
  }

  /*
   * 유효하지 않은 MAC Protocol Version을 포함한 MPDU 전달 시 실패하는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  memcpy(mpdu, g_1400_bytes_wsm_mpdu_with_max_hdr, g_1400_bytes_wsm_mpdu_with_max_hdr_size);
  mpdu_size = g_1400_bytes_wsm_mpdu_with_max_hdr_size;
  mpdu[0] |= 1; // 원래는 b1b0가 b00이어야 한다.
  payload = Dot3_ParseWSMMPDU(mpdu,
                              mpdu_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLowerLayerProtocolVersion);

  /*
   * 유효하지 않은 Framce Contrl Type을 포함한 MPDU 전달 시 실패하는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  memcpy(mpdu, g_1400_bytes_wsm_mpdu_with_max_hdr, g_1400_bytes_wsm_mpdu_with_max_hdr_size);
  mpdu_size = g_1400_bytes_wsm_mpdu_with_max_hdr_size;
  mpdu[0] |= (1 << 2); // 원래는 b3b2가 b10이어야 한다.
  payload = Dot3_ParseWSMMPDU(mpdu,
                              mpdu_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLowerLayerFrameType);

  /*
   * 유효하지 않은 Framce Contrl Subtype을 포함한 MPDU 전달 시 실패하는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  memcpy(mpdu, g_1400_bytes_wsm_mpdu_with_max_hdr, g_1400_bytes_wsm_mpdu_with_max_hdr_size);
  mpdu_size = g_1400_bytes_wsm_mpdu_with_max_hdr_size;
  mpdu[0] |= (1 << 4); // 원래는 b7~b4가 b1000이어야 한다.
  payload = Dot3_ParseWSMMPDU(mpdu,
                              mpdu_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLowerLayerFrameType);

  /*
   * 유효하지 않은 ADDR3을 포함한 MPDU 전달 시 실패하는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  memcpy(mpdu, g_1400_bytes_wsm_mpdu_with_max_hdr, g_1400_bytes_wsm_mpdu_with_max_hdr_size);
  mpdu_size = g_1400_bytes_wsm_mpdu_with_max_hdr_size;
  memset(mpdu + 16, 0x03, MAC_ALEN);
  payload = Dot3_ParseWSMMPDU(mpdu,
                              mpdu_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_NotWildcardBSSID);

  /*
   * 유효하지 않은 LLC Type을 포함한 MPDU 전달 시 실패하는 것을 확인한다.
   */
  expected_size = 1400 - kDot3WSMHdrSize_Max;
  memcpy(mpdu, g_1400_bytes_wsm_mpdu_with_max_hdr, g_1400_bytes_wsm_mpdu_with_max_hdr_size);
  mpdu_size = g_1400_bytes_wsm_mpdu_with_max_hdr_size;
  mpdu[26]--;
  mpdu[27]--;
  payload = Dot3_ParseWSMMPDU(mpdu,
                              mpdu_size,
                              &params,
                              &payload_size,
                              &wsr_registered,
                              &ret);
  ASSERT_TRUE(payload == NULL);
  ASSERT_EQ(ret, -kDot3Result_NotSupportedEtherType);


  ReleaseTestEnv();
}
