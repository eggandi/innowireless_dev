/**
 * @file
 * @brief Dot3_ConstructWSM() API에 대한 단위테스트 구현 파일
 * @date 2020-07-19
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_ConstructWSM() API 호출 시 필수정보를 포함한 WSM이 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ConstructWSM, MANDATORY_PARAMS)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 필수필드만 포함하는 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = 0;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSM() API 호출 시 옵션정보를 포함한 WSM이 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ConstructWSM, OPTIONAL_PARAMS)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 확장필드를 포함하는 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = 172;
  params.datarate = kDot3DataRate_6Mbps;
  params.transmit_power = 30;
  params.psid = kDot3PSID_Max;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_max_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_max_hdr, wsm_size));
  free(wsm);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSM() API 호출 시 전달되는 PSID 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSM, CHECK_PARAM_PSID)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 최소값 전달 시 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  /*
   * 최대값 전달 시 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = 172;
  params.datarate = kDot3DataRate_6Mbps;
  params.transmit_power = 30;
  params.psid = kDot3PSID_Max;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_max_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_max_hdr, wsm_size));
  free(wsm);

  /*
   * 1바이트 길이 PSID 전달 시 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = 0;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_1byte_psid_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_1byte_psid, wsm_size));
  free(wsm);

  /*
   * 2바이트 길이 PSID 전달 시 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = 128;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_2bytes_psid_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_2bytes_psid, wsm_size));
  free(wsm);

  /*
   * 3바이트 길이 PSID 전달 시 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = 16512;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_3bytes_psid_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_3bytes_psid, wsm_size));
  free(wsm);

  /*
   * 4바이트 길이 PSID 전달 시 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = 2113664;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_4bytes_psid_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_4bytes_psid, wsm_size));
  free(wsm);

  /*
   * 유효하지 않은 PSID 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Max + 1;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidPSID);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSM() API 호출 시 전달되는 Channel Number 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSM, CHECK_PARAM_CHAN_NUM)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * NA를 명시하면 확장필드가 포함되지 않는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  /*
   * 유효하지 않은 Channel Number 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_Max + 1;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidChannelNumber);

  /*
   * 유효한 Channel Number 전달 시 해당 확장필드를 포함하는 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = 172;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_chan_num_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_chan_num_ext_hdr, wsm_size));
  free(wsm);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSM() API 호출 시 전달되는 DataRate 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSM, CHECK_PARAM_DATARATE)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * NA를 명시하면 확장필드가 포함되지 않는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  /*
   * 유효하지 않은 DataRate 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = 0;
  params.transmit_power = kDot3Power_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidDataRate);

  /*
   * 유효한 DataRate 전달 시 해당 확장필드를 포함하는 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_6Mbps;
  params.transmit_power = kDot3Power_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_datarate_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_datarate_ext_hdr, wsm_size));
  free(wsm);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSM() API 호출 시 전달되는 Transmit Power Used 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSM, CHECK_PARAM_TX_POWER)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * NA를 명시하면 확장필드가 포함되지 않는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  /*
   * 유효하지 않은 Tx Power 전달 시 실패하는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3Power_Max + 1;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidPower);

  /*
   * 유효한 Tx Power 전달 시 해당 확장필드를 포함하는 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = 30;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_tx_power_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_tx_power_ext_hdr, wsm_size));
  free(wsm);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSM() API 호출 시 전달되는 payload, payload_size 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSM, CHECK_PARAMS_PAYLOAD_AND_SIZE)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 초기화
   */
  for (size_t i = 0; i < sizeof(payload); i++) {
    payload[i] = (uint8_t)(i % 16);
  }

  /*
   * payload 파라미터를 NULL로 전달하면(payload_size가 0이 아니더라도) 0 바이트 페이로드가 수납된 WSM이 생성되는 것을 확인한다.
   */
  payload_size = 10;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, NULL, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  /*
   * payload_size 파라미터를 최소값(0)으로 전달하면(payload가 NULL이 아니더라도)
   * 0 바이트 페이로드가 수납된 WSM이 생성되는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  /*
   * 생성된 WSM의 길이가 MIB에 설정된 최대값(kDot3WSMSize_DefaultMaxInMIB)과 같도록
   * payload_size 파라미터 값을 전달하면 WSM이 정상적으로 생성되는 것을 확인한다.
   */
  payload_size = kDot3WSMSize_DefaultMaxInMIB - (kDot3WSMHdrSize_Min + 1)/*최소 헤더에서 Length 필드 길이가 1증가*/;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_1400_bytes_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_1400_bytes_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  /*
   * 생성된 WSM의 길이가 MIB에 설정된 최대값(kDot3WSMSize_DefaultMaxInMIB)보다 크도록
   * payload_size 파라미터 값을 전달하면 실패하는 것을 확인한다.
   */
  payload_size = kDot3WSMSize_DefaultMaxInMIB - kDot3WSMHdrSize_Min;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMSize);

  /*
   * 유효하지 않은 payload_size 값을 전달하면 실패하는 것을 확인한다.
   */
  payload_size = kDot3WSMPayloadSize_Max + 1;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMPayloadSize);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSM() API 호출 시 NULL 파라미터가 전달될 때의 동작을 확인한다.
 */
TEST(Dot3_ConstructWSM, CHECK_PARAMS_NULL)
{
  InitTestEnv();

  /*
   * 파라미터
   */
  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * params 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(NULL, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * wsm_size 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, NULL, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * ret 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  payload_size = 0;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, NULL);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * payload 파라미터를 NULL로 전달하면(payload_size가 0이 아니더라도) 0 바이트 페이로드가 수납된 WSM이 생성되는 것을 확인한다.
   */
  payload_size = 10;
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, NULL, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(wsm_size, g_min_size_wsm_with_no_ext_hdr_size);
  ASSERT_TRUE(CompareBytes(wsm, g_min_size_wsm_with_no_ext_hdr, wsm_size));
  free(wsm);

  ReleaseTestEnv();
}
