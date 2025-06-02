/** 
 * @file
 * @brief Dot3_ConstructWSMMPDU() API에 대한 단위테스트 구현 파일
 * @date 2020-07-20
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 필수정보를 포함한 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, MANDATORY_PARAMS)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 필수필드만 포함하는 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = 0;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 옵션정보를 포함한 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, OPTIONAL_PARAMS)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 확장필드를 포함하는 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = 172;
  params.wsm.datarate = kDot3DataRate_6Mbps;
  params.wsm.transmit_power = 30;
  params.wsm.psid = kDot3PSID_Max;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_max_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_max_hdr, mpdu_size));
  free(mpdu);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 전달되는 목적지 MAC 주소 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAM_DST_MAC_ADDR)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 브로드캐스트 전달 시 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.mac.priority = kDot3Priority_Min;
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 유니캐스트 전달 시 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  uint8_t expected[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_Min];
  memcpy(expected, g_min_size_wsm_mpdu_with_no_ext_hdr, sizeof(expected));
  memcpy(expected + 4, g_ucast_addr, MAC_ALEN);
  expected[24] = 0x00;
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_ucast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.mac.priority = kDot3Priority_Min;
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, sizeof(expected));
  ASSERT_TRUE(CompareBytes(mpdu, expected, mpdu_size));
  free(mpdu);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 전달되는 Priority 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAM_PRIORITY)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 최소값 전달 시 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.mac.priority = kDot3Priority_Min;
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 최대값 전달 시 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  uint8_t expected[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_Min];
  memcpy(expected, g_min_size_wsm_mpdu_with_no_ext_hdr, sizeof(expected));
  expected[24] = 0x20 | (kDot3Priority_Max & 0xf);
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.mac.priority = kDot3Priority_Max;
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, sizeof(expected));
  ASSERT_TRUE(CompareBytes(mpdu, expected, mpdu_size));
  free(mpdu);

  /*
   * 유효하지 않은 값 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.mac.priority = kDot3Priority_Max + 1;
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidPriority);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 전달되는 PSID 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAM_PSID)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 최소값 전달 시 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 최대값 전달 시 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = 172;
  params.wsm.datarate = kDot3DataRate_6Mbps;
  params.wsm.transmit_power = 30;
  params.wsm.psid = kDot3PSID_Max;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_max_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_max_hdr, mpdu_size));
  free(mpdu);

  /*
   * 유효하지 않은 PSID 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Max + 1;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidPSID);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 전달되는 Channel Number 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAM_CHAN_NUM)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * NA를 명시하면 확장필드가 포함되지 않는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 유효하지 않은 Channel Number 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_Max + 1;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidChannelNumber);

  /*
   * 유효한 Channel Number 전달 시 해당 확장필드를 포함하는 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = 172;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_chan_num_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_chan_num_ext_hdr, mpdu_size));
  free(mpdu);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 전달되는 DataRate 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAM_DATARATE)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * NA를 명시하면 확장필드가 포함되지 않는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 유효하지 않은 DataRate 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = 0;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidDataRate);

  /*
   * 유효한 DataRate 전달 시 해당 확장필드를 포함하는 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_6Mbps;
  params.wsm.transmit_power = kDot3Power_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_datarate_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_datarate_ext_hdr, mpdu_size));
  free(mpdu);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 전달되는 Transmit Power Used 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAM_TX_POWER)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * NA를 명시하면 확장필드가 포함되지 않는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 유효하지 않은 Tx Power 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3Power_Max + 1;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidPower);

  /*
   * 유효한 Tx Power 전달 시 해당 확장필드를 포함하는 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = 30;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_tx_power_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_tx_power_ext_hdr, mpdu_size));
  free(mpdu);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 전달되는 payload, payload_size 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAMS_PAYLOAD_AND_SIZE)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 초기화
   */
  for (size_t i = 0; i < sizeof(payload); i++) {
    payload[i] = (uint8_t)(i % 16);
  }

  /*
   * payload 파라미터를 NULL로 전달하면(payload_size가 0이 아니더라도) 0 바이트 페이로드가 수납된 WSM MPDU가 생성되는 것을 확인한다.
   */
  payload_size = 10;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, NULL, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * payload_size 파라미터를 최소값(0)으로 전달하면(payload가 NULL이 아니더라도)
   * 0 바이트 페이로드가 수납된 WSM MPDU가 생성되는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 생성된 WSM의 길이가 MIB에 설정된 최대값(kDot3WSMSize_DefaultMaxInMIB)과 같도록
   * payload_size 파라미터 값을 전달하면 WSM MPDU가 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = kDot3WSMSize_DefaultMaxInMIB - (kDot3WSMHdrSize_Min + 1)/*최소 헤더에서 Length 필드 길이가 1증가*/;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_1400_bytes_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_1400_bytes_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  /*
   * 생성된 WSM의 길이가 MIB에 설정된 최대값(kDot3WSMSize_DefaultMaxInMIB)보다 크도록
   * payload_size 파라미터 값을 전달하면 실패하는 것을 확인한다.
   */
  payload_size = kDot3WSMSize_DefaultMaxInMIB - kDot3WSMHdrSize_Min;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMSize);

  /*
   * 유효하지 않은 payload_size 값을 전달하면 실패하는 것을 확인한다.
   */
  payload_size = kDot3WSMPayloadSize_Max + 1;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMPayloadSize);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSMMPDU() API 호출 시 NULL 파라미터가 전달될 때의 동작을 확인한다.
 */
TEST(Dot3_ConstructWSMMPDU, CHECK_PARAMS_NULL)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t mpdu_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *mpdu;
  struct Dot3MACAndWSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * params 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(NULL, payload, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * mpdu_size 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, NULL, &ret);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * ret 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload_size = 0;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, payload, payload_size, &mpdu_size, NULL);
  ASSERT_TRUE(mpdu == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * payload 파라미터를 NULL로 전달하면(payload_size가 0이 아니더라도) 0 바이트 페이로드가 수납된 WSM MPDU가 생성되는 것을 확인한다.
   */
  payload_size = 10;
  memcpy(params.mac.dst_mac_addr, g_bcast_addr, MAC_ALEN);
  memcpy(params.mac.src_mac_addr, g_my_addr, MAC_ALEN);
  params.wsm.chan_num = kDot3ChannelNumber_NA;
  params.wsm.datarate = kDot3DataRate_NA;
  params.wsm.transmit_power = kDot3DataRate_NA;
  params.wsm.psid = kDot3PSID_Min;
  mpdu = Dot3_ConstructWSMMPDU(&params, NULL, payload_size, &mpdu_size, &ret);
  ASSERT_TRUE(mpdu != NULL);
  ASSERT_EQ(mpdu_size, g_min_size_wsm_mpdu_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(mpdu, g_min_size_wsm_mpdu_with_no_ext_hdr, mpdu_size));
  free(mpdu);

  ReleaseTestEnv();
}
