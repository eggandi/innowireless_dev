/**
 * @file
 * @brief Dot3_SetWSMMaxLength() API에 대한 단위테스트 구현 파일
 * @date 2020-07-20
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_SetWSMMaxLength() API 호출 시 정상적으로 등록되는 것을 확인한다.
 */
TEST(Dot3_SetWSMMaxLength, NORMAL)
{
  InitTestEnv();

  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값 설정
   */
  for (size_t i = 0; i < sizeof(payload); i++) {
    payload[i] = (uint8_t)(i % 16);
  }

  /*
   * 기본 WSM Max length 값 크기의 WSM이 정상적으로 생성되는 것을 확인한다.
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
   * WSM Max length 값보다 큰 WSM은 생성되지 않은 것을 확인한다.
   */
  payload_size = kDot3WSMSize_DefaultMaxInMIB - (kDot3WSMHdrSize_Min);
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSMSize);

  /*
   * WSM max length 값을 증가시키면 WSM이 생성되는 것을 확인한다.
   */
  size_t wsm_max_len = kDot3WSMSize_DefaultMaxInMIB + 1;
  ASSERT_EQ(Dot3_SetWSMMaxLength(wsm_max_len), kDot3Result_Success);
  payload_size = kDot3WSMSize_DefaultMaxInMIB - (kDot3WSMHdrSize_Min);
  params.chan_num = kDot3ChannelNumber_NA;
  params.datarate = kDot3DataRate_NA;
  params.transmit_power = kDot3DataRate_NA;
  params.psid = kDot3PSID_Min;
  wsm = Dot3_ConstructWSM(&params, payload, payload_size, &wsm_size, &ret);
  ASSERT_TRUE(wsm != NULL);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(wsm_size, wsm_max_len);
  free(wsm);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_SetWSMMaxLength() API 호출 시 전달되는 max_len 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_SetWSMMaxLength, CHECK_PARAM_MAX_LEN)
{
  InitTestEnv();

  int ret;
  size_t wsm_size;
  Dot3WSMPayloadSize payload_size;
  uint8_t payload[kDot3WSMPayloadSize_Max], *wsm;
  struct Dot3WSMConstructParams params;
  memset(&params, 0, sizeof(params));

  /*
   * 페이로드 기대값 설정
   */
  for (size_t i = 0; i < sizeof(payload); i++) {
    payload[i] = (uint8_t)(i % 16);
  }

  /*
   * 최소값을 전달하면 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetWSMMaxLength(kDot3WSMSize_Min), kDot3Result_Success);

  /*
   * 최대값을 전달하면 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetWSMMaxLength(kDot3WSMSize_Max), kDot3Result_Success);

  /*
   * 최소값보다 작은 값을 전달하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetWSMMaxLength(kDot3WSMSize_Min - 1), -kDot3Result_InvalidWSMMaxLength);

  /*
   * 최대값보다 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetWSMMaxLength(kDot3WSMSize_Max + 1), -kDot3Result_InvalidWSMMaxLength);

  ReleaseTestEnv();
}
