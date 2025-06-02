/** 
 * @file
 * @brief Dot3_ConstructWSA() API에 대한 단위테스트 구현 파일
 * @date 2020-07-21
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief 두 PCI의 값을 비교한다.
 */
static bool ComparePCI(struct Dot3PCI *pci1, struct Dot3PCI *pci2)
{
  EXPECT_EQ(pci1->operating_class, pci2->operating_class);
  EXPECT_EQ(pci1->chan_num, pci2->chan_num);
  EXPECT_EQ(pci1->transmit_power_level, pci2->transmit_power_level);
  EXPECT_EQ(pci1->datarate, pci2->datarate);
  EXPECT_EQ(pci1->adaptable_datarate, pci2->adaptable_datarate);
  EXPECT_EQ(pci1->present.chan_access, pci2->present.chan_access);
  EXPECT_EQ(pci1->present.edca_param_set, pci2->present.edca_param_set);
  if (pci1->operating_class != pci2->operating_class) { return false; }
  if (pci1->chan_num != pci2->chan_num) { return false; }
  if (pci1->transmit_power_level != pci2->transmit_power_level) { return false; }
  if (pci1->datarate != pci2->datarate) { return false; }
  if (pci1->adaptable_datarate != pci2->adaptable_datarate) { return false; }
  if (pci1->present.chan_access != pci2->present.chan_access) { return false; }
  if (pci1->present.edca_param_set != pci2->present.edca_param_set) { return false; }
  if (pci1->present.chan_access) {
    EXPECT_EQ(pci1->chan_access, pci2->chan_access);
    if (pci1->chan_access != pci2->chan_access) { return false; }
  }
  if (pci1->present.edca_param_set) {
    for (unsigned int i = 0; i < 4; i++) {
      EXPECT_EQ(pci1->edca_param_set.record[i].acm, pci2->edca_param_set.record[i].acm);
      EXPECT_EQ(pci1->edca_param_set.record[i].aifsn, pci2->edca_param_set.record[i].aifsn);
      EXPECT_EQ(pci1->edca_param_set.record[i].ecwmin, pci2->edca_param_set.record[i].ecwmin);
      EXPECT_EQ(pci1->edca_param_set.record[i].ecwmax, pci2->edca_param_set.record[i].ecwmax);
      EXPECT_EQ(pci1->edca_param_set.record[i].txoplimit, pci2->edca_param_set.record[i].txoplimit);
      if (pci1->edca_param_set.record[i].acm != pci2->edca_param_set.record[i].acm) { return false; }
      if (pci1->edca_param_set.record[i].aifsn != pci2->edca_param_set.record[i].aifsn) { return false; }
      if (pci1->edca_param_set.record[i].ecwmin != pci2->edca_param_set.record[i].ecwmin) { return false; }
      if (pci1->edca_param_set.record[i].ecwmax != pci2->edca_param_set.record[i].ecwmax) { return false; }
      if (pci1->edca_param_set.record[i].txoplimit != pci2->edca_param_set.record[i].txoplimit) { return false; }
    }
  }
  return true;
}


/**
 * @brief 각 정보가 최소값을 갖고 확장정보를 포함하지 않는 샘플 PSR을 등록한다.
 */
static bool RegisterSampleMinPSRWithNoExtensions()
{
  int ret;
  bool res;

  /*
   * 하나의 PSR을 등록한다.
   */
  struct Dot3PSR psr, psr_r;
  memset(&psr, 0, sizeof(psr));
  psr.wsa_id = 0;
  psr.psid = 0;
  psr.service_chan_num = 172;
  psr.ip_service = false;
  ret = Dot3_AddPSR(&psr);
  EXPECT_EQ(ret, 1);
  if (ret != 1) { return false; }

  /*
   * 등록된 PSR 정보를 확인한다.
   */
  ret = Dot3_GetPSRWithPSID(psr.psid, &psr_r);
  EXPECT_EQ(ret, kDot3Result_Success);
  if (ret != kDot3Result_Success) { return false; }
  res = CompareBytes((uint8_t *)&psr, (uint8_t *)&psr_r, sizeof(psr_r));
  EXPECT_TRUE(res);
  if (!res) { return false; }

  return true;
}


/**
 * @brief 각 정보가 최대값을 갖고 모든 확장정보를 포함하는 샘플 PCI들을 설정한다.
 */
static bool RegisterSampleMinPCIWithNoExtensions()
{
  int ret;
  bool res;
  Dot3PCINum pci_num = Dot3_GetPCINum();

  struct Dot3PCI pci, pci_r;
  memset(&pci, 0, sizeof(pci));
  pci.chan_num = 172;
  pci.operating_class = 17;
  pci.transmit_power_level = kDot3Power_Min;
  pci.datarate = kDot3DataRate_3Mbps;
  pci.adaptable_datarate = false;
  ret = Dot3_SetPCI(&pci);
  EXPECT_EQ(ret, (int)pci_num);
  if (ret != (int)pci_num) { return false; }

  memset(&pci_r, 0, sizeof(pci_r));
  ret = Dot3_GetPCIWithChannelNumber(pci.chan_num, &pci_r);
  EXPECT_EQ(ret, kDot3Result_Success);
  if (ret != kDot3Result_Success) { return false; }
  res = ComparePCI(&pci, &pci_r);
  EXPECT_TRUE(res);
  if (!res) { return false; }

  return true;
}



/**
 * @brief 각 정보가 최대값을 갖고 모든 확장정보를 포함하는 샘플 PSR들을 등록한다.
 */
static bool RegisterSampleMaxPSRsWithAllExtensions()
{
  int ret;

  /*
   * PSR을 등록가능한 최대개수만큼 등록한다.
   *  - wsa_id를 최소값부터 최대값 사이에서 순차적으로 증가시키며 각 PSR에 대입한다.
   */
  struct Dot3PSR psrs[kDot3PSRNum_Max], psr_r;
  memset(psrs, 0, sizeof(psrs));
  for (unsigned int i = 0; i < kDot3PSRNum_Max; i++) {
    psrs[i].psid = i;
    psrs[i].wsa_id = (i % (kDot3WSAIdentifier_Max + 1));  // PSR 별로 wsa_id를 다르게 준다.
    psrs[i].service_chan_num = 172 + (i % 13);
    psrs[i].present.psc = true;
    psrs[i].present.provider_mac_addr = true;
    psrs[i].present.rcpi_threshold = true;
    psrs[i].present.wsa_cnt_threshold = true;
    psrs[i].present.wsa_cnt_threshold_interval = true;
    psrs[i].ip_service = true;
    psrs[i].psc.len = strlen("0123456789012345678901234567890");
    memcpy(psrs[i].psc.psc, "0123456789012345678901234567890", psrs[i].psc.len);
    memcpy(psrs[i].ipv6_address, g_my_ipv6_addr, IPv6_ALEN);
    psrs[i].service_port = 65535;
    memcpy(psrs[i].provider_mac_addr, g_my_addr, MAC_ALEN);
    psrs[i].rcpi_threshold = kDot3RCPI_Max;
    psrs[i].wsa_cnt_threshold = kDot3WSACountThreshold_Max;
    psrs[i].wsa_cnt_threshold_interval = kDot3WSACountThresholdInterval_Max;
    ret = Dot3_AddPSR(&psrs[i]);
    EXPECT_EQ(ret, (int)(i + 1));
    if (ret != (int)(i + 1)) { return false; }
  }
  EXPECT_EQ(Dot3_GetPSRNum(), kDot3PSRNum_Max);
  if (Dot3_GetPSRNum() != kDot3PSRNum_Max) { return false; }

  /*
   * 등록된 PSR 정보를 확인한다.
   */
  for (unsigned int i = 0; i < kDot3PSRNum_Max; i++) {
    memset(&psr_r, 0, sizeof(psr_r));
    EXPECT_EQ(Dot3_GetPSRWithPSID(psrs[i].psid, &psr_r), kDot3Result_Success);
    EXPECT_TRUE(CompareBytes((uint8_t *)&(psrs[i]), (uint8_t *)&psr_r, sizeof(psr_r)));
    if (Dot3_GetPSRWithPSID(psrs[i].psid, &psr_r) != kDot3Result_Success) { return false; }
    if (!CompareBytes((uint8_t *)&(psrs[i]), (uint8_t *)&psr_r, sizeof(psr_r))) { return false; }
  }
  return true;
}


/**
 * @brief 각 정보가 최대값을 갖고 모든 확장정보를 포함하는 샘플 PCI들을 설정한다.
 */
static bool RegisterSampleMaxPCIsWithAllExtensions()
{
  int ret;
  bool res;
  Dot3PCINum pci_num = Dot3_GetPCINum();

  struct Dot3PCI pcis[8], pci_r;
  memset(pcis, 0, sizeof(pcis));
  for (unsigned int i = 0; i < 8; i++) {
    switch (i) {
      case 0: pcis[i].chan_num = 174; break;
      case 1: pcis[i].chan_num = 177; break;
      case 2: pcis[i].chan_num = 180; break;
      case 3: pcis[i].chan_num = 183; break;
      case 4: pcis[i].chan_num = 173; break;
      case 5: pcis[i].chan_num = 176; break;
      case 6: pcis[i].chan_num = 179; break;
      case 7: pcis[i].chan_num = 182; break;
    }
    if ((pcis[i].chan_num % 2) == 0) {
      pcis[i].operating_class = 17;
      pcis[i].datarate = 54;
    } else {
      pcis[i].operating_class = 18;
      pcis[i].datarate = 108;
    }
    pcis[i].transmit_power_level = 127;
    pcis[i].adaptable_datarate = true;
    pcis[i].present.chan_access = true;
    pcis[i].present.edca_param_set = true;
    pcis[i].chan_access = kDot3ProviderChannelAccess_AlternatingTimeSlot0Only;
    for (unsigned int j = 0; j < 4; j++) {
      pcis[i].edca_param_set.record[j].aci = j;
      pcis[i].edca_param_set.record[j].acm = false;
      pcis[i].edca_param_set.record[j].aifsn = kDot3AIFSN_Max;
      pcis[i].edca_param_set.record[j].ecwmax = kDot3ECW_Max;
      pcis[i].edca_param_set.record[j].ecwmin = kDot3ECW_Max;
      pcis[i].edca_param_set.record[j].txoplimit = kDot3TXOPLimit_Max;
    }
    ret = Dot3_SetPCI(&(pcis[i]));
    EXPECT_EQ(ret, (int)pci_num);
    if (ret != (int)pci_num) { return false; }
  }

  for (unsigned int i = 0; i < 8; i++) {
    memset(&pci_r, 0, sizeof(pci_r));
    ret = Dot3_GetPCIWithChannelNumber(pcis[i].chan_num, &pci_r);
    EXPECT_EQ(ret, kDot3Result_Success);
    if (ret != kDot3Result_Success) { return false; }
    res = ComparePCI(&(pcis[i]), &pci_r);
    EXPECT_TRUE(res);
    if (!res) { return false; }
  }

  return true;
}


/**
 * @brief 각 정보가 최소값을 갖고 확장필드를 포함하지 않은 WSA를 생성하기 위한 생성파라미터를 설정한다.
 */
static void PrepareConstructParamsForMinWSAWithNoExtensions(struct Dot3ConstructWSAParams *params)
{
  memset(params, 0, sizeof(struct Dot3ConstructWSAParams));
  params->hdr.wsa_id = kDot3WSAIdentifier_Min;
  params->hdr.content_count = kDot3WSAContentCount_Min;
}


/**
 * @brief 각 정보가 최소값을 갖고 모든 확장필드를 포함한 WSA를 생성하기 위한 생성파라미터를 설정한다.
 */
static void PrepareConstructParamsForMinWSAWithAllExtensions(struct Dot3ConstructWSAParams *params)
{
  memset(params, 0, sizeof(struct Dot3ConstructWSAParams));
  params->hdr.extensions.repeat_rate = true;
  params->hdr.extensions.twod_location = true;
  params->hdr.extensions.threed_location = true;
  params->hdr.extensions.advertiser_id = true;
  params->present.wra = true;
  params->hdr.wsa_id = kDot3WSAIdentifier_Min;
  params->hdr.content_count = kDot3WSAContentCount_Min;
  params->hdr.repeat_rate = kDot3WSARepeatRate_Min;
  params->hdr.twod_location.latitude = kDot3Latitude_Min;
  params->hdr.twod_location.longitude = kDot3Longitude_Min;
  params->hdr.threed_location.latitude = kDot3Latitude_Min;
  params->hdr.threed_location.longitude = kDot3Longitude_Min;
  params->hdr.threed_location.elevation = kDot3Elevation_Min;
  params->hdr.advertiser_id.len = strlen("0");
  memcpy(params->hdr.advertiser_id.id, "0", params->hdr.advertiser_id.len);
  params->wra.router_lifetime = kDot3WRARouterLifetime_Min;
  memcpy(params->wra.ip_prefix, g_my_ipv6_addr, IPv6_ALEN);
  params->wra.ip_prefix_len = kDot3IPv6PrefixLen_Min;
  memcpy(params->wra.default_gw, g_my_ipv6_addr, IPv6_ALEN);
  memcpy(params->wra.primary_dns, g_my_ipv6_addr, IPv6_ALEN);
  params->wra.present.gateway_mac_addr = true;
  params->wra.present.secondary_dns = true;
  memcpy(params->wra.gateway_mac_addr, g_my_addr, MAC_ALEN);
  memcpy(params->wra.secondary_dns, g_my_ipv6_addr, IPv6_ALEN);
}


/**
 * @brief 각 정보가 최대값을 갖고 모든 확장필드를 포함한 WSA를 생성하기 위한 생성파라미터를 설정한다.
 */
static void PrepareConstructParamsForMaxWSAWithAllExtensions(struct Dot3ConstructWSAParams *params)
{
  memset(params, 0, sizeof(struct Dot3ConstructWSAParams));
  params->hdr.extensions.repeat_rate = true;
  params->hdr.extensions.twod_location = true;
  params->hdr.extensions.threed_location = true;
  params->hdr.extensions.advertiser_id = true;
  params->present.wra = true;
  params->hdr.wsa_id = kDot3WSAIdentifier_Max; // wsa_id = max인 PSR 정보만 WSA에 수납되어야 한다.
  params->hdr.content_count = kDot3WSAContentCount_Max;
  params->hdr.repeat_rate = kDot3WSARepeatRate_Max;
  params->hdr.twod_location.latitude = kDot3Latitude_Max;
  params->hdr.twod_location.longitude = kDot3Longitude_Max;
  params->hdr.threed_location.latitude = kDot3Latitude_Max;
  params->hdr.threed_location.longitude = kDot3Longitude_Max;
  params->hdr.threed_location.elevation = kDot3Elevation_Max;
  params->hdr.advertiser_id.len = strlen("01234567890123456789012345678901");
  memcpy(params->hdr.advertiser_id.id, "01234567890123456789012345678901", params->hdr.advertiser_id.len);
  params->wra.router_lifetime = kDot3WRARouterLifetime_Max;
  memcpy(params->wra.ip_prefix, g_my_ipv6_addr, IPv6_ALEN);
  params->wra.ip_prefix_len = kDot3IPv6PrefixLen_Max;
  memcpy(params->wra.default_gw, g_my_ipv6_addr, IPv6_ALEN);
  memcpy(params->wra.primary_dns, g_my_ipv6_addr, IPv6_ALEN);
  params->wra.present.gateway_mac_addr = true;
  params->wra.present.secondary_dns = true;
  memcpy(params->wra.gateway_mac_addr, g_my_addr, MAC_ALEN);
  memcpy(params->wra.secondary_dns, g_my_ipv6_addr, IPv6_ALEN);
}


/**
 * @brief 각 정보가 최소값을 갖고 확장필드를 포함하지 않은 WSA를 생성하기 위한 준비를 수행한다.
 */
static bool PrepareForMinWSAWithNoExtensions(struct Dot3ConstructWSAParams *params)
{
  Dot3_DeleteAllPSRs();
  Dot3PSRNum psr_num = Dot3_GetPSRNum();
  EXPECT_EQ(psr_num, 0UL);
  if (psr_num != 0UL) { return false; }

  bool ret = RegisterSampleMinPSRWithNoExtensions();
  EXPECT_TRUE(ret);
  if (!ret) { return false; }

  ret = RegisterSampleMinPCIWithNoExtensions();
  EXPECT_TRUE(ret);
  if (!ret) { return false; }

  PrepareConstructParamsForMinWSAWithNoExtensions(params);

  return true;
}


/**
 * @brief 각 정보가 최소값을 갖고 일부 확장필드(헤더, WRA)를 포함한 WSA를 생성하기 위한 준비를 수행한다.
 */
static bool PrepareForMinWSAWithSomeExtensions(struct Dot3ConstructWSAParams *params)
{
  Dot3_DeleteAllPSRs();
  Dot3PSRNum psr_num = Dot3_GetPSRNum();
  EXPECT_EQ(psr_num, 0UL);
  if (psr_num != 0UL) { return false; }

  bool ret = RegisterSampleMinPSRWithNoExtensions();
  EXPECT_TRUE(ret);
  if (!ret) { return false; }

  ret = RegisterSampleMinPCIWithNoExtensions();
  EXPECT_TRUE(ret);
  if (!ret) { return false; }

  PrepareConstructParamsForMinWSAWithAllExtensions(params);

  return true;
}


/**
 * @brief 각 정보가 최대값을 갖고 모든 확장필드(헤더, ServiceInfo, ChannelInfo, WRA)를 포함한 WSA를 생성하기 위한 준비를 수행한다.
 */
static bool PrepareForMaxWSAWithAllExtensions(struct Dot3ConstructWSAParams *params)
{
  Dot3_DeleteAllPSRs();
  Dot3PSRNum psr_num = Dot3_GetPSRNum();
  EXPECT_EQ(psr_num, 0UL);
  if (psr_num != 0UL) { return false; }

  bool ret = RegisterSampleMaxPSRsWithAllExtensions();
  EXPECT_TRUE(ret);
  if (!ret) { return false; }

  ret = RegisterSampleMaxPCIsWithAllExtensions();
  EXPECT_TRUE(ret);
  if (!ret) { return false; }

  PrepareConstructParamsForMaxWSAWithAllExtensions(params);

  return true;
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 각 정보가 최소값을 갖고 필수필드만을 포함한 WSA가 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ConstructWSA, MIN_WSA_WITH_NO_EXT)
{
  InitTestEnv();

  int ret;
  size_t wsa_size;
  uint8_t *wsa;
  struct Dot3ConstructWSAParams params;

  /*
   * 각 정보가 최소값을 갖고 확장필드를 포함하지 않은 WSA를 생성하기 위한 준비를 수행한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithNoExtensions(&params));

  /*
   * WSA 생성 시 정상적으로 생성되는 것을 확인한다.
   */
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_no_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_no_ext, wsa_size));
  free(wsa);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 각 정보가 최소값을 갖고 확장필드를 일부 포함한 WSA가 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ConstructWSA, MIN_WSA_WITH_SOME_EXT)
{
  InitTestEnv();

  int ret;
  size_t wsa_size;
  uint8_t *wsa;
  struct Dot3ConstructWSAParams params;

  /*
   * 각 정보가 최소값을 갖고 일부 확장필드를 포함하는 WSA를 생성하기 위한 준비를 수행한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));

  /*
   * WSA 생성 시 정상적으로 생성되는 것을 확인한다.
   */
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 각 정보가 최대값을 갖고 확장필드를 모두 포함한 WSA가 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ConstructWSA, MAX_WSA_WITH_ALL_EXT)
{
  InitTestEnv();

  int ret;
  size_t wsa_size;
  uint8_t *wsa;
  struct Dot3ConstructWSAParams params;

  /*
   * 각 정보가 최대값을 갖고 모든 확장필드를 포함하는 WSA를 생성하기 위한 준비를 수행한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));

  /*
   * WSA 생성 시 정상적으로 생성되는 것을 확인한다.
   */
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 wsa_id 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_WSA_ID)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * wsa_id = 0(최소값)를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * wsa_id = 15(최대값)를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 유효하지 않은 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.wsa_id = kDot3WSAIdentifier_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSAIdentifier);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 WSA content count 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_WSA_CONTENT_COUNT)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * content count = 0(최소값)를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * content count = 15(최대값)를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 유효하지 않은 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.content_count = kDot3WSAContentCount_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSAContentCount);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 RepeatRate 옵션 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_REPEAT_RATE)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * repeat rate = 0(최소값)를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * repeat rate = 255(최대값)를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 유효하지 않은 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.repeat_rate = kDot3WSARepeatRate_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidRepeatRate);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 2DLocation 옵션 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_2D_LOCATION)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * Latitude, Longitude 최소값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * Latitude, Longitude 최대값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 너무 작은 Latitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.twod_location.latitude = kDot3Latitude_Min - 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLatitude);

  /*
   * 너무 큰 Latitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.twod_location.latitude = kDot3Latitude_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLatitude);

  /*
   * 너무 작은 Longitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.twod_location.longitude = kDot3Longitude_Min - 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLongitude);

  /*
   * 너무 큰 Longitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.twod_location.longitude = kDot3Longitude_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLongitude);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 3DLocation 옵션 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_3D_LOCATION)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * Latitude, Longitude, Elevation 최소값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * Latitude, Longitude, Elevation 최대값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 너무 작은 Latitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.threed_location.latitude = kDot3Latitude_Min - 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLatitude);

  /*
   * 너무 큰 Latitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.threed_location.latitude = kDot3Latitude_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLatitude);

  /*
   * 너무 작은 Longitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.threed_location.longitude = kDot3Longitude_Min - 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLongitude);

  /*
   * 너무 큰 Longitude 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.threed_location.longitude = kDot3Longitude_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidLongitude);

  /*
   * 너무 작은 Elevation 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.threed_location.elevation = kDot3Elevation_Min - 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidElevation);

  /*
   * 너무 큰 Elevation 값 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.threed_location.elevation = kDot3Elevation_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidElevation);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 Advertiser ID 옵션 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_ADVERTISER_ID)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * 최소길이 Advertiser ID를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * 최대길이 Advertiser ID를 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 너무 짧은 Advertiser ID 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.advertiser_id.len = strlen("");
  memcpy(params.hdr.advertiser_id.id, "", params.hdr.advertiser_id.len);
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidAdvertiserIDLen);

  /*
   * 너무 긴 Advertiser ID 전달 시 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMaxWSAWithAllExtensions(&params);
  params.hdr.advertiser_id.len = strlen("012345678901234567890123456789012");
  memcpy(params.hdr.advertiser_id.id, "012345678901234567890123456789012", params.hdr.advertiser_id.len);
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidAdvertiserIDLen);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 WRA Router lifetime 옵션 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_ROUTER_LIFETIME)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * 최소값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * 최대값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 너무 작은 값을 전달하면 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMinWSAWithAllExtensions(&params);
  params.wra.router_lifetime = kDot3WRARouterLifetime_Min - 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWRARouterLifetime);

  /*
   * 너무 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMinWSAWithAllExtensions(&params);
  params.wra.router_lifetime = kDot3WRARouterLifetime_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidWRARouterLifetime);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 전달되는 IP prefix len 옵션 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAM_IP_PREFIX_LEN)
{
  InitTestEnv();

  int ret;
  size_t wsa_size, expected_size;
  uint8_t *wsa, expected[kDot3WSMPayloadSize_Max];
  struct Dot3ConstructWSAParams params;

  /*
   * 최소값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMinWSAWithSomeExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_min_wsa_with_some_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_min_wsa_with_some_ext, wsa_size));
  free(wsa);

  /*
   * 최대값을 전달하면 WSA 생성이 성공하는 것을 확인한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa != NULL);
  ASSERT_EQ(wsa_size, g_max_wsa_with_all_ext_size);
  ASSERT_TRUE(CompareBytes(wsa, g_max_wsa_with_all_ext, wsa_size));
  free(wsa);

  /*
   * 너무 작은 값을 전달하면 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMinWSAWithAllExtensions(&params);
  params.wra.ip_prefix_len = kDot3IPv6PrefixLen_Min - 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidIPv6PrefixLen);

  /*
   * 너무 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  PrepareConstructParamsForMinWSAWithAllExtensions(&params);
  params.wra.ip_prefix_len = kDot3IPv6PrefixLen_Max + 1;
  wsa = Dot3_ConstructWSA(&params, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_InvalidIPv6PrefixLen);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ConstructWSA() API 호출 시 NULL 파라미터 전달에 따른 동작을 확인한다.
 */
TEST(Dot3_ConstructWSA, CHECK_PARAMS_NULL)
{
  InitTestEnv();

  int ret;
  size_t wsa_size;
  uint8_t *wsa;
  struct Dot3ConstructWSAParams params;

  /*
   * 샘플 WSA 생성을 위한 준비를 수행한다.
   */
  ASSERT_TRUE(PrepareForMaxWSAWithAllExtensions(&params));

  /*
   * params 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  wsa = Dot3_ConstructWSA(NULL, &wsa_size, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * wsa_size 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  wsa = Dot3_ConstructWSA(&params, NULL, &ret);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * ret 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  wsa = Dot3_ConstructWSA(&params, &wsa_size, NULL);
  ASSERT_TRUE(wsa == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  ReleaseTestEnv();
}
