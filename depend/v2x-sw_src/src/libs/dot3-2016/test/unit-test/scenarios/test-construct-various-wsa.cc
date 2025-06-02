/** 
 * @file
 * @brief 다양한 형태의 WSA 생성에 대한 단위테스트 구현 파일
 * @date 2020-08-01
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief 동일한 Channel Info를 참조하는 2개 이상의 Service Info를 포함하는 WSA를 생성하는 기능 테스트
 */
TEST(CONSTRUCT_VARIOUS_WSA, SERV_INFOS_SHARING_CHAN_INFO)
{
  extern uint8_t g_wsa_with_serv_infos_sharing_chan_info[];
  extern size_t g_wsa_with_serv_infos_sharing_chan_info_size;

  InitTestEnv();

  int ret;
  size_t wsa_size;
  uint8_t *wsa;
  struct Dot3ConstructWSAParams params;

  /*
   * PCI들을 설정한다.
   */
  Dot3PCINum pci_num = Dot3_GetPCINum();
  Dot3PCI pci;
  memset(&pci, 0, sizeof(pci));
  // 172번 채널에 대한 PCI
  pci.operating_class = 17;
  pci.chan_num = 172;
  pci.transmit_power_level = -128;
  pci.datarate = kDot3DataRate_3Mbps;
  pci.adaptable_datarate = false;
  ASSERT_EQ(Dot3_SetPCI(&pci), (int)pci_num);
  // 175번 채널에 대한 PCI
  pci.operating_class = 18;
  pci.chan_num = 175;
  pci.transmit_power_level = -127;
  pci.datarate = kDot3DataRate_12Mbps;
  pci.adaptable_datarate = true;
  ASSERT_EQ(Dot3_SetPCI(&pci), (int)pci_num);

  /*
   * PSR들을 등록한다.
   *  - 3개의 PSR이 동일한 채널을 사용한다.
   */
  struct Dot3PSR psr;
  memset(&psr, 0, sizeof(psr));
  // 1번째 PSR
  psr.wsa_id = 1;
  psr.psid = 0;
  psr.service_chan_num = 172;
  psr.ip_service = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), 1);
  // 2번째 PSR
  psr.wsa_id = 1;
  psr.psid = 1;
  psr.service_chan_num = 172;
  psr.ip_service = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), 2);
  // 3번째 PSR
  psr.wsa_id = 1;
  psr.psid = 2;
  psr.service_chan_num = 172;
  psr.ip_service = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), 3);
  // 4번째 PSR
  psr.wsa_id = 1;
  psr.psid = 3;
  psr.service_chan_num = 175;
  psr.ip_service = false;
  ASSERT_EQ(Dot3_AddPSR(&psr), 4);

  /*
   * WSA 생성 시 기대하던 대로 생성되는 것을 확인한다.
   */
  memset(&params, 0, sizeof(params));
  params.hdr.wsa_id = 1;
  params.hdr.content_count = 0;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
//  ASSERT_EQ(wsa_size, g_wsa_with_serv_infos_sharing_chan_info_size);
  ASSERT_TRUE(CompareBytes(wsa, g_wsa_with_serv_infos_sharing_chan_info, g_wsa_with_serv_infos_sharing_chan_info_size));
  free(wsa);

  ReleaseTestEnv();
}
