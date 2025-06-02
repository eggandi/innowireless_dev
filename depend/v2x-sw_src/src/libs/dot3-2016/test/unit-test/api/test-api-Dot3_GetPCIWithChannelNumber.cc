/** 
 * @file
 * @brief Dot3_GetPCIWithChannelNumber() API에 대한 단위테스트 구현 파일
 * @date 2020-07-14
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_GetPCIWithChannelNumber() API 호출 시 저장되어 있는 PCI의 채널번호를 전달하면 정상적으로 반환되는 것을 확인한다.
 */
TEST(Dot3_GetPCIWithChannelNumber, REGISTERED_PCI)
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
   * (사전 단계) PCI를 업데이트 한다.
   */
  ASSERT_EQ(Dot3_SetPCI(&pci), (int)pci_num);

  /*
   * API 호출 시 성공하는 것을 확인한다.
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
 * @brief Dot3_GetPCIWithChannelNumber() API 호출 시 저장되어 있지 않은 PCI의 채널번호를 전달하면 반환되지 않는 것을 확인한다.
 */
TEST(Dot3_GetPCIWithChannelNumber, NOT_REGISTERED_PCI)
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
   * API 호출 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCIWithChannelNumber(chan_num, &pci_r), -kDot3Result_NoSuchPCI);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_GetPCIWithChannelNumber() API 호출 시 유효하지 않은 채널번호를 전달하면 정상적으로 예외처리되는 것을 확인한다.
 */
TEST(Dot3_GetPCIWithChannelNumber, INVALID_CHAN_NUM)
{
  InitTestEnv();

  struct Dot3PCI pci, pci_r;
  Dot3ChannelNumber chan_num = kDot3ChannelNumber_Max + 1;
  Dot3PCINum pci_num = kDot3ChannelNumber_KoreaV2XMax - kDot3ChannelNumber_KoreaV2XMin + 1; // 초기 개수

  /*
   * (사전 단계) 저장되어 있는 PCI의 개수를 확인하여 기본 개수가 저장되어 있는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCINum(), pci_num);

  /*
   * API 호출 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCIWithChannelNumber(chan_num, &pci_r), -kDot3Result_InvalidChannelNumber);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_GetPCIWithChannelNumber() API 호출 시 널 파라미터를 전달하면 정상적으로 예외처리되는 것을 확인한다.
 */
TEST(Dot3_GetPCIWithChannelNumber, NULL_PCI)
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
   * API 호출 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetPCIWithChannelNumber(chan_num, NULL), -kDot3Result_NullParameters);

  ReleaseTestEnv();
}




 
