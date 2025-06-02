/**
 * @file
 * @brief Dot3_ChangePSR() API에 대한 단위테스트 구현 파일
 * @date 2020-07-18
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_ChangePSR() API 호출 시 해당 PSR이 정상적으로 변경되는 것을 확인한다.
 */
TEST(Dot3_ChangePSR, NORMAL)
{
  InitTestEnv();

  Dot3PSRNum psr_num = 0;
  Dot3PSR psr, psr_r;
  Dot3WSAIdentifier wsa_id = 0;
  Dot3PSID psid = 0;
  Dot3ChannelNumber service_chan_num = 178;
  Dot3IPv6Address ip_addr = { 0x20,0x01,0x0d,0xb8,0x85,0xa3,0x08,0xd3,0x13,0x19,0x8a,0x2e,0x03,0x70,0x73,0x48 };
  uint16_t service_port = 20000;
  Dot3MACAddress mac_addr = { 0x00,0x01,0x02,0x03,0x04,0x05 };
  Dot3RCPI rcpi_threshold = 10;
  Dot3WSACountThreshold wsa_cnt_threshold = 11;
  Dot3WSACountThresholdInterval wsa_cnt_threshold_interval = 12;

  /*
   * 등록할 PSR을 세팅한다.
   */
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  SetPSROptionalPSC("test", &psr);
  SetPSROptionalIPService(ip_addr, service_port, &psr);
  SetPSROptionalProviderMACAddress(mac_addr, &psr);
  SetPSROptionalRCPIThreshold(rcpi_threshold, &psr);
  SetPSROptionalWSACountThreshold(wsa_cnt_threshold, &psr);
  SetPSROptionalWSACountThresholdInterval(wsa_cnt_threshold_interval, &psr);

  /*
   * PSR을 등록한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  /*
   * PSR이 정상적으로 변경되는 것을 확인한다.
   */
  SetPSROptionalPSC("change", &psr);
  ASSERT_EQ(Dot3_ChangePSR(psid, "change"), kDot3Result_Success);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ChangePSR() API 호출 시 전달되는 PSID에 따른 동작을 확인한다.
 */
TEST(Dot3_ChangePSR, CHECK_PARAM_PSID)
{
  InitTestEnv();

  Dot3PSRNum psr_num = 0;
  Dot3PSR psr, psr_r;
  Dot3WSAIdentifier wsa_id = 0;
  Dot3PSID psid = 0;
  Dot3ChannelNumber service_chan_num = 178;
  Dot3IPv6Address ip_addr = { 0x20,0x01,0x0d,0xb8,0x85,0xa3,0x08,0xd3,0x13,0x19,0x8a,0x2e,0x03,0x70,0x73,0x48 };
  uint16_t service_port = 20000;
  Dot3MACAddress mac_addr = { 0x00,0x01,0x02,0x03,0x04,0x05 };
  Dot3RCPI rcpi_threshold = 10;
  Dot3WSACountThreshold wsa_cnt_threshold = 11;
  Dot3WSACountThresholdInterval wsa_cnt_threshold_interval = 12;

  /*
   * 등록할 PSR을 세팅한다.
   */
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  SetPSROptionalPSC("test", &psr);
  SetPSROptionalIPService(ip_addr, service_port, &psr);
  SetPSROptionalProviderMACAddress(mac_addr, &psr);
  SetPSROptionalRCPIThreshold(rcpi_threshold, &psr);
  SetPSROptionalWSACountThreshold(wsa_cnt_threshold, &psr);
  SetPSROptionalWSACountThresholdInterval(wsa_cnt_threshold_interval, &psr);

  /*
   * PSR을 등록한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  /*
   * 유효하지 않은 PSID 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ChangePSR(kDot3PSID_Max + 1, "change"), -kDot3Result_InvalidPSID);

  /*
   * 등록되어 있지 않은 PSID 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ChangePSR(psid + 1, "change"), -kDot3Result_NoSuchPSR);

  /*
   * 정확한 PSID 전달 시 PSR이 정상적으로 변경되는 것을 확인한다.
   */
  SetPSROptionalPSC("change", &psr);
  ASSERT_EQ(Dot3_ChangePSR(psid, "change"), kDot3Result_Success);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ChangePSR() API 호출 시 전달되는 PSC에 따른 동작을 확인한다.
 */
TEST(Dot3_ChangePSR, CHECK_PARAM_PSC)
{
  InitTestEnv();

  Dot3PSRNum psr_num = 0;
  Dot3PSR psr, psr_r;
  Dot3WSAIdentifier wsa_id = 0;
  Dot3PSID psid = 0;
  Dot3ChannelNumber service_chan_num = 178;
  Dot3IPv6Address ip_addr = { 0x20,0x01,0x0d,0xb8,0x85,0xa3,0x08,0xd3,0x13,0x19,0x8a,0x2e,0x03,0x70,0x73,0x48 };
  uint16_t service_port = 20000;
  Dot3MACAddress mac_addr = { 0x00,0x01,0x02,0x03,0x04,0x05 };
  Dot3RCPI rcpi_threshold = 10;
  Dot3WSACountThreshold wsa_cnt_threshold = 11;
  Dot3WSACountThresholdInterval wsa_cnt_threshold_interval = 12;

  /*
   * 등록할 PSR을 세팅한다.
   */
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  SetPSROptionalPSC("test", &psr);
  SetPSROptionalIPService(ip_addr, service_port, &psr);
  SetPSROptionalProviderMACAddress(mac_addr, &psr);
  SetPSROptionalRCPIThreshold(rcpi_threshold, &psr);
  SetPSROptionalWSACountThreshold(wsa_cnt_threshold, &psr);
  SetPSROptionalWSACountThresholdInterval(wsa_cnt_threshold_interval, &psr);

  /*
   * PSR을 등록한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  /*
   * NULL PSC 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ChangePSR(psid, NULL), -kDot3Result_NullParameters);

  /*
   * 최소길이(0) PSC 전달 시 정상적으로 변경되는 것을 확인한다.
   */
  SetPSROptionalPSC("", &psr);
  ASSERT_EQ(Dot3_ChangePSR(psid, ""), kDot3Result_Success);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  /*
   * 최대길이(kDot3PSCLen_Max) PSC 전달 시 정상적으로 변경되는 것을 확인한다.
   */
  SetPSROptionalPSC("0123456789012345678901234567890", &psr);
  ASSERT_EQ(Dot3_ChangePSR(psid, "0123456789012345678901234567890"), kDot3Result_Success);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  /*
   * 최대길이보다 큰(kDot3PSCLen_Max + 1) PSC 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ChangePSR(psid, "01234567890123456789012345678901"), -kDot3Result_InvalidPSCLen);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  ReleaseTestEnv();
}
