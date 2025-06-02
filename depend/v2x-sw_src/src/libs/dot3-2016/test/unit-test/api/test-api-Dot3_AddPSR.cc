/** 
 * @file
 * @brief Dot3_AddPSR() API에 대한 단위테스트 구현 파일
 * @date 2020-07-14
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_AddPSR() API 호출 시 필수정보가 정상적으로 등록되는 것을 확인한다.
 */
TEST(Dot3_AddPSR, MANDATORY_PARAMS)
{
  InitTestEnv();

  Dot3PSRNum psr_num = 0;
  Dot3PSR psr, psr_r;
  Dot3WSAIdentifier wsa_id = 0;
  Dot3PSID psid = 0;
  Dot3ChannelNumber service_chan_num = 178;

  /*
   * 등록할 PSR의 필수정보를 세팅한다.
   */
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);

  /*
   * API 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);

  /*
   * 등록된 PSR을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);

  /*
   * 샘플 PSR과 반환된 PSR 정보를 비교한다.
   */
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 옵션정보가 정상적으로 등록되는 것을 확인한다.
 */
TEST(Dot3_AddPSR, OPTIONAL_PARAMS)
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
   * API 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);

  /*
   * 등록된 PSR을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);

  /*
   * 샘플 PSR과 반환된 PSR 정보를 비교한다.
   */
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 널 파라미터를 전달하면 실패하는 것을 확인한다.
 */
TEST(Dot3_AddPSR, NULL_PSR)
{
  InitTestEnv();

  Dot3PSRNum psr_num = 0;
  Dot3PSR psr, psr_r;
  Dot3WSAIdentifier wsa_id = 0;
  Dot3PSID psid = 0;
  Dot3ChannelNumber service_chan_num = 178;

  /*
   * 널 파라미터로 API 호출 시 실패하는 것을 확인한다.
   */
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  ASSERT_EQ(Dot3_AddPSR(NULL), -kDot3Result_NullParameters);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 WSA ID 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, MANDATORY_WSA_ID_PARAMS)
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
   * 최소값(kDot3WSAIdentifier_Min)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.wsa_id = kDot3WSAIdentifier_Min;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_EQ(psr.wsa_id, psr_r.wsa_id);

  /*
   * 최대값(kDot3WSAIdentifier_Max)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.wsa_id = kDot3WSAIdentifier_Max;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_EQ(psr.wsa_id, psr_r.wsa_id);

  /*
   * 최대값보다 큰 값(kDot3WSAIdentifier_Max+1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.wsa_id = kDot3WSAIdentifier_Max + 1;
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_InvalidWSAIdentifier);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 PSID 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, MANDATORY_PSID_PARAMS)
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
   * 최소값(kDot3PSID_Min)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = psid = kDot3PSID_Min;;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_EQ(psr.psid, psr_r.psid);

  /*
   * 최대값(kDot3PSID_Max)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = psid = kDot3PSID_Max;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_EQ(psr.psid, psr_r.psid);

  /*
   * 최대값보다 큰 값(kDot3PSID_Max+1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = psid = kDot3PSID_Max + 1;
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_InvalidPSID);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 Service Channel Number 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, MANDATORY_SERVICE_CHAN_NUM_PARAMS)
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
   * 허용되는 최소값(kDot3ChannelNumber_KoreaV2XMin)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   *  - PCI가 설정되어 있는 최소채널번호
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.service_chan_num = kDot3ChannelNumber_KoreaV2XMin;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_EQ(psr.service_chan_num, psr_r.service_chan_num);

  /*
   * 허용되는 최대값(kDot3ChannelNumber_KoreaV2XMax)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   *  - PCI가 설정되어 있는 최대채널번호
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.service_chan_num = kDot3ChannelNumber_KoreaV2XMax;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_EQ(psr.service_chan_num, psr_r.service_chan_num);

  /*
   * 허용되는 최소값보다 작은 값(kDot3ChannelNumber_KoreaV2XMin-1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   *  - PCI가 설정되어 있는 최소채널번호 - 1
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.service_chan_num = kDot3ChannelNumber_KoreaV2XMin - 1;
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_NoRelatedChannelInfo);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  /*
   * 허용되는 최대값보다 큰 값(kDot3ChannelNumber_KoreaV2XMax+1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   *  - PCI가 설정되어 있는 최대채널번호 + 1
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.service_chan_num = kDot3ChannelNumber_KoreaV2XMax + 1;
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_NoRelatedChannelInfo);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  /*
   * 최대값보다 큰 값(kDot3ChannelNumber_Max+1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  psr.service_chan_num = kDot3ChannelNumber_Max + 1;
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_InvalidChannelNumber);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 IP service 필수정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, MANDATORY_IP_SERVICE_PARAMS)
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
   * IP service를 설정하지 않아도 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.ip_service = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_FALSE(psr_r.ip_service);

  /*
   * IP service을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalIPService(ip_addr, service_port, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.ip_service);
  ASSERT_TRUE(CompareBytes(psr.ipv6_address, psr_r.ipv6_address, IPv6_ALEN));
  ASSERT_EQ(psr.service_port, psr_r.service_port);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 PSC 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, OPTIONAL_PSC_PARAMS)
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
   * PSC를 설정하지 않아도 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  psr.present.psc = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_FALSE(psr_r.present.psc);

  /*
   * PSC 길이를 최소값(0)으로 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  psid++;
  memset(&psr_r, 0, sizeof(psr_r));
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  SetPSROptionalPSC("", &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.psc);
  ASSERT_EQ(psr_r.psc.len, kDot3PSCLen_Min);

  /*
   * PSC 길이를 최대값(31바이트)으로 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  psid++;
  memset(&psr_r, 0, sizeof(psr_r));
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  SetPSROptionalPSC("0123456789012345678901234567890", &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.psc);
  ASSERT_EQ(psr_r.psc.len, kDot3PSCLen_Max);

  /*
   * PSC 길이를 최대값보다 크게 설정하면 PSR이 등록되지 않는 것을 확인한다.
   */
  psid++;
  memset(&psr_r, 0, sizeof(psr_r));
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  psr.present.psc = true;
  psr.psc.len = kDot3PSCLen_Max + 1;
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_InvalidPSCLen);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 Provider MAC address 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, OPTIONAL_PROVIDER_MAC_ADDRESS_PARAMS)
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
   * Provider MAC address를 설정하지 않아도 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  psr.present.provider_mac_addr = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_FALSE(psr_r.present.provider_mac_addr);

  /*
   * Provider MAC address를 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  psid++;
  memset(&psr_r, 0, sizeof(psr_r));
  SetPSRMandatoryInfo(wsa_id, psid, service_chan_num, &psr);
  SetPSROptionalProviderMACAddress(mac_addr, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.provider_mac_addr);
  ASSERT_TRUE(CompareBytes(psr.provider_mac_addr, psr_r.provider_mac_addr, MAC_ALEN));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 RCPI threshold 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, OPTIONAL_RCPI_THRESHOLD_PARAMS)
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
   * RCPI threshold를 설정하지 않아도 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.present.rcpi_threshold = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_FALSE(psr_r.present.rcpi_threshold);

  /*
   * 최소값(kDot3RCPI_Min)를 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalRCPIThreshold(kDot3RCPI_Min, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.rcpi_threshold);
  ASSERT_EQ(psr.rcpi_threshold, psr_r.rcpi_threshold);

  /*
   * 최대값(kDot3RCPI_Max)를 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalRCPIThreshold(kDot3RCPI_Max, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.rcpi_threshold);
  ASSERT_EQ(psr.rcpi_threshold, psr_r.rcpi_threshold);

  /*
   * 최대값보다 큰 값(kDot3RCPI_Max+1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalRCPIThreshold(kDot3RCPI_Max + 1, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_InvalidWSARCPIThreshold);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 WSA Count threshold 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, OPTIONAL_WSA_COUNT_THRESHOLD_PARAMS)
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
   * WSA Count threshold를 설정하지 않아도 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.present.wsa_cnt_threshold = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_FALSE(psr_r.present.wsa_cnt_threshold);

  /*
   * 최소값(kDot3WSACountThreshold_Min)를 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalWSACountThreshold(kDot3WSACountThreshold_Min, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.wsa_cnt_threshold);
  ASSERT_EQ(psr.wsa_cnt_threshold, psr_r.wsa_cnt_threshold);

  /*
   * 최대값(kDot3WSACountThreshold_Max)를 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalWSACountThreshold(kDot3WSACountThreshold_Max, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.wsa_cnt_threshold);
  ASSERT_EQ(psr.wsa_cnt_threshold, psr_r.wsa_cnt_threshold);

  /*
   * 최대값보다 큰 값(kDot3WSACountThreshold_Max+1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalWSACountThreshold(kDot3WSACountThreshold_Max + 1, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_InvalidWSACountThreshold);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 전달되는 WSA Count threshold interval 옵션정보에 따른 동작을 확인한다.
 */
TEST(Dot3_AddPSR, OPTIONAL_WSA_COUNT_THRESHOLD_INTERVAL_PARAMS)
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
   * WSA Count threshold interval을 설정하지 않아도 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.present.wsa_cnt_threshold_interval = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_FALSE(psr_r.present.wsa_cnt_threshold_interval);

  /*
   * 최소값(kDot3WSACountThresholdInterval_Min)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalWSACountThresholdInterval(kDot3WSACountThresholdInterval_Min, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.wsa_cnt_threshold_interval);
  ASSERT_EQ(psr.wsa_cnt_threshold_interval, psr_r.wsa_cnt_threshold_interval);

  /*
   * 최대값(kDot3WSACountThresholdInterval_Max)을 설정하면 PSR이 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalWSACountThresholdInterval(kDot3WSACountThresholdInterval_Max, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  ASSERT_TRUE(psr_r.present.wsa_cnt_threshold_interval);
  ASSERT_EQ(psr.wsa_cnt_threshold_interval, psr_r.wsa_cnt_threshold_interval);

  /*
   * 최대값보다 큰 값(kDot3WSACountThresholdInterval_Max+1)을 설정하면 PSR이 등록되지 않는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  SetPSROptionalWSACountThresholdInterval(kDot3WSACountThresholdInterval_Max + 1, &psr);
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_InvalidWSACountThresholdInterval);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 이미 등록된 PSID에 대해 등록하면 실패하는 것을 확인한다.
 */
TEST(Dot3_AddPSR, DUPLICATE_PSID)
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
   * PSR을 등록하면 정상적으로 등록되는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  /*
   * 동일한 PSID를 갖는 PSR을 등록하면 실패하는 것을 확인한다(기존 PSR은 유지되는 것을 확인한다)
   */
  memset(&psr_r, 0, sizeof(psr_r));
  Dot3PSR psr2;
  SetPSRMandatoryInfo(wsa_id + 1, psid, service_chan_num, &psr2);
  ASSERT_EQ(Dot3_AddPSR(&psr2), -kDot3Result_DuplicatedPSR);
  ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
  ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
  ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddPSR() API 호출 시 테이블이 가득 찬 상태에서 등록하면 실패하는 것을 확인한다.
 */
TEST(Dot3_AddPSR, TABLE_FULL)
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
   * PSR을 최대개수만큼 등록한다.
   */
  for (unsigned int i = 0; i < kDot3PSRNum_Max; i++) {
    memset(&psr_r, 0, sizeof(psr_r));
    psr.psid = ++psid;
    ASSERT_EQ(Dot3_AddPSR(&psr), (int)++psr_num);
    ASSERT_EQ(Dot3_GetPSRNum(), psr_num);
    ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), kDot3Result_Success);
    ASSERT_TRUE(ComparePSRMandatoryInfo(&psr, &psr_r));
    ASSERT_TRUE(ComparePSROptionalInfo(&psr, &psr_r));
  }
  ASSERT_EQ(Dot3_GetPSRNum(), kDot3PSRNum_Max);

  /*
   * PSR을 등록하면 실패하는 것을 확인한다.
   */
  memset(&psr_r, 0, sizeof(psr_r));
  psr.psid = ++psid;
  ASSERT_EQ(Dot3_AddPSR(&psr), -kDot3Result_PSRTableFull);
  ASSERT_EQ(Dot3_GetPSRNum(), kDot3PSRNum_Max);
  ASSERT_EQ(Dot3_GetPSRWithPSID(psid, &psr_r), -kDot3Result_NoSuchPSR);

  ReleaseTestEnv();
}

