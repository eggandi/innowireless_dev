/** 
 * @file
 * @brief Dot3_SetPCI() API에 대한 단위테스트 구현 파일
 * @date 2020-07-14
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_SetPCI() API 호출 시 기존 채널에 대한 PCI를 전달하면, PCI가 정상적으로 업데이트 되는 것을 확인한다.
 */
TEST(Dot3_SetPCI, UPDATE_PCI)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), (int)pci_num);

  /*
   * 저장 개수가 그대로인 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * 설정한 채널에 대한 PCI 정보를 가져온다.
   */
  ASSERT_EQ(Dot3_GetPCIWithChannelNumber(chan_num, &pci_r), kDot3Result_Success);

  /*
   * 샘플 PCI의 정보와 반환된 PCI의 정보가 동일한 것을 확인한다.
   */
  ASSERT_TRUE(ComparePCIMandatoryInfo(&pci, &pci_r));
  ASSERT_TRUE(ComparePCIOptionalEDCAParameterSet(&pci, &pci_r));
  ASSERT_TRUE(ComparePCIOptionalChannelAccess(&pci, &pci_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_SetPCI() API 호출 시 새로운 채널에 대한 PCI를 전달하면, PCI가 정상적으로 추가되는 것을 확인한다.
 */
TEST(Dot3_SetPCI, ADD_PCI)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 170;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), (int)(pci_num + 1));

  /*
   * 저장 개수가 하나 증가한 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num + 1);

  /*
   * 설정한 채널에 대한 PCI 정보를 가져온다.
   */
  ASSERT_EQ(Dot3_GetPCIWithChannelNumber(chan_num, &pci_r), kDot3Result_Success);

  /*
   * 샘플 PCI의 정보와 반환된 PCI의 정보가 동일한 것을 확인한다.
   */
  ASSERT_TRUE(ComparePCIMandatoryInfo(&pci, &pci_r));
  ASSERT_TRUE(ComparePCIOptionalEDCAParameterSet(&pci, &pci_r));
  ASSERT_TRUE(ComparePCIOptionalChannelAccess(&pci, &pci_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_SetPCI() API 호출 시 널 파라미터를 전달하면, 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, NULL_PARAMS)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(NULL), -kDot3Result_NullParameters);

  ReleaseTestEnv();
}


#if 0 // NOTE:: 국내에서는 Operating class로 어떤 값을 사용할지 정의되어 있지 않으므로, 유효성 검사를 생략한다.
/**
 * @brief Dot3_SetPCI() API 호출 시 유효하지 않은 Operating class를 전달하면, 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, INVALID_OP_CLASS)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 유효하지 않은 Operating class를 셋팅한다.
   */
  SetPCIMandatoryInfo(10/*유효하지 않은 operating class*/, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidOperatingClass);

  ReleaseTestEnv();
}
#endif


/**
 * @brief Dot3_SetPCI() API 호출 시 유효하지 않은 채널번호를 전달하면, 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, INVALID_CHAN_NUM)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 유효하지 않은 채널번호를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, kDot3ChannelNumber_Max + 1, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidChannelNumber);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_SetPCI() API 호출 시 유효하지 않은 송신파워를 전달하면, 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, INVALID_TX_POWER)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 너무 작은 송신파워를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, kDot3Power_Min - 1, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidPower);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 너무 큰 송신파워를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, kDot3Power_Max + 1, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidPower);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_SetPCI() API 호출 시 유효하지 않은 DataRate를 전달하면, 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, INVALID_DATARATE)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 유효하지 않은 DataRate를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, 0/*DataRate*/, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidDataRate);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_SetPCI() API 호출 시 유효하지 않은 Channel Access를 전달하면, 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, INVALID_CHANNEL_ACCESS)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 유효하지 않은 Channel Access를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_Max + 1, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidChannelAccess);

  ReleaseTestEnv();
}



/**
 * @brief Dot3_SetPCI() API 호출 시 유효하지 않은 EDCA Parameter Set를 전달하면, 정상적으로 예외처리하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, INVALID_EDCA_PARAMETER_SET)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 유효하지 않은 AIFSN를 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, kDot3AIFSN_Max + 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidAIFSN);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 유효하지 않은 ECWmin을 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, kDot3ECW_Max + 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidECWMin);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - 유효하지 않은 ECWmax을 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, kDot3ECW_Max + 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidECWMax);

  /*
   * (사전 단계) 설정할 PCI를 셋팅한다.
   *  - ECWmax를 ECWmin보다 작게 셋팅한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, chan_num, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 2, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);

  /*
   * API() 호출 시 정상적으로 예외처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_InvalidECWMax);

  ReleaseTestEnv();
}


/**
 * @brief 테이블이 꽉 찬 상태에서 Dot3_SetPCI() API 호출 시 실패하는 것을 확인한다.
 */
TEST(Dot3_SetPCI, TABLE_FULL)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = 178;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * (사전 단계) 최대 개수만큼 설정한다.
   */
  int i = 0;
  for (i = 0; i < (int)(kDot3PCINum_Max - pci_num); i++) {
    SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, kDot3ChannelNumber_Min + i, -10, kDot3DataRate_6Mbps, true, &pci);
    SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
    SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
    SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
    SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
    SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);
    ASSERT_EQ(Dot3_SetPCI(&pci), (int)(pci_num + i + 1));
  }

  /*
   * (사전 단계) 저장 개수가 최대인 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), kDot3PCINum_Max);

  /*
   * 새로운 PCI 추가 시 실패하는 것을 확인한다.
   */
  SetPCIMandatoryInfo(kDot3OperatingClass_5G_10MHz, kDot3ChannelNumber_Min + i, -10, kDot3DataRate_6Mbps, true, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BE, true, 1, 1, 1, 1, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_BK, false, 2, 2, 2, 2, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VI, true, 3, 3, 3, 3, &pci);
  SetPCIOptionalEDCAParameterSet(kDot3ACI_VO, false, 4, 4, 4, 4, &pci);
  SetPCIOptionalChannelAccess(kDot3ProviderChannelAccess_AlternatingTimeSlot0Only, &pci);
  ASSERT_EQ(Dot3_SetPCI(&pci), -kDot3Result_PCITableFull);

  ReleaseTestEnv();
}
