/** 
 * @file
 * @brief Dot3_ParseWSA() API에 대한 단위테스트 구현 파일
 * @date 2020-07-23
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_ParseWSA() API 호출 시 각 정보가 최소값을 갖고 필수필드만을 포함한 WSA가 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ParseWSA, MIN_WSA_WITH_NO_EXT)
{
  InitTestEnv();

  struct Dot3ParseWSAParams params;

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(g_min_wsa_with_no_ext, g_min_wsa_with_no_ext_size, &params), kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSA() API 호출 시 각 정보가 최소값을 갖고 확장필드를 일부 포함한 WSA가 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ParseWSA, MIN_WSA_WITH_SOME_EXT)
{
  InitTestEnv();

  struct Dot3ParseWSAParams params;

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(g_min_wsa_with_some_ext, g_min_wsa_with_some_ext_size, &params), kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_TRUE(params.hdr.extensions.repeat_rate);
  ASSERT_EQ(params.hdr.repeat_rate, kDot3WSARepeatRate_Min);
  ASSERT_TRUE(params.hdr.extensions.twod_location);
  ASSERT_EQ(params.hdr.twod_location.latitude, kDot3Latitude_Min);
  ASSERT_EQ(params.hdr.twod_location.longitude, kDot3Longitude_Min);
  ASSERT_TRUE(params.hdr.extensions.threed_location);
  ASSERT_EQ(params.hdr.threed_location.latitude, kDot3Latitude_Min);
  ASSERT_EQ(params.hdr.threed_location.longitude, kDot3Longitude_Min);
  ASSERT_EQ(params.hdr.threed_location.elevation, kDot3Elevation_Min);
  ASSERT_TRUE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.hdr.advertiser_id.len, strlen("0"));
  ASSERT_TRUE(CompareString(params.hdr.advertiser_id.id, "0"));
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_TRUE(params.present.wra);
  ASSERT_EQ(params.wra.router_lifetime, kDot3WRARouterLifetime_Min);
  ASSERT_TRUE(CompareBytes(params.wra.ip_prefix, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_EQ(params.wra.ip_prefix_len, kDot3IPv6PrefixLen_Min);
  ASSERT_TRUE(CompareBytes(params.wra.default_gw, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_TRUE(CompareBytes(params.wra.primary_dns, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_TRUE(params.wra.present.secondary_dns);
  ASSERT_TRUE(CompareBytes(params.wra.secondary_dns, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_TRUE(params.wra.present.gateway_mac_addr);
  ASSERT_TRUE(CompareBytes(params.wra.gateway_mac_addr, g_my_addr, MAC_ALEN));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSA() API 호출 시 각 정보가 최대값을 갖고 확장필드를 모두 포함한 WSA가 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ParseWSA, MAX_WSA_WITH_ALL_EXT)
{
  InitTestEnv();

  struct Dot3ParseWSAParams params;

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(g_max_wsa_with_all_ext, g_max_wsa_with_all_ext_size, &params), kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Max);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Max);
  ASSERT_TRUE(params.hdr.extensions.repeat_rate);
  ASSERT_EQ(params.hdr.repeat_rate, kDot3WSARepeatRate_Max);
  ASSERT_TRUE(params.hdr.extensions.twod_location);
  ASSERT_EQ(params.hdr.twod_location.latitude, kDot3Latitude_Max);
  ASSERT_EQ(params.hdr.twod_location.longitude, kDot3Longitude_Max);
  ASSERT_TRUE(params.hdr.extensions.threed_location);
  ASSERT_EQ(params.hdr.threed_location.latitude, kDot3Latitude_Max);
  ASSERT_EQ(params.hdr.threed_location.longitude, kDot3Longitude_Max);
  ASSERT_EQ(params.hdr.threed_location.elevation, kDot3Elevation_Max);
  ASSERT_TRUE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.hdr.advertiser_id.len, strlen("01234567890123456789012345678901"));
  ASSERT_TRUE(CompareString(params.hdr.advertiser_id.id, "01234567890123456789012345678901"));
  ASSERT_EQ(params.wsi_num, 8UL);
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[0]), 15, 1));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[1]), 31, 2));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[2]), 47, 3));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[3]), 63, 4));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[4]), 79, 5));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[5]), 95, 6));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[6]), 111, 7));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[7]), 127, 8));
  ASSERT_EQ(params.wci_num, 8UL);
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[0]), 17, 174, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[1]), 18, 177, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[2]), 17, 180, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[3]), 18, 183, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[4]), 18, 173, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[5]), 17, 176, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[6]), 18, 179, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[7]), 17, 182, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(params.present.wra);
  ASSERT_EQ(params.wra.router_lifetime, kDot3WRARouterLifetime_Max);
  ASSERT_TRUE(CompareBytes(params.wra.ip_prefix, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_EQ(params.wra.ip_prefix_len, kDot3IPv6PrefixLen_Max);
  ASSERT_TRUE(CompareBytes(params.wra.default_gw, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_TRUE(CompareBytes(params.wra.primary_dns, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_TRUE(params.wra.present.secondary_dns);
  ASSERT_TRUE(params.wra.present.gateway_mac_addr);
  ASSERT_TRUE(CompareBytes(params.wra.secondary_dns, g_my_ipv6_addr, IPv6_ALEN));
  ASSERT_TRUE(CompareBytes(params.wra.gateway_mac_addr, g_my_addr, MAC_ALEN));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSA() API 호출 시 전달되는 NULL 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ParseWSA, CHECK_PARAMS_NULL)
{
  InitTestEnv();

  struct Dot3ParseWSAParams params;

  /*
   * wsa 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(NULL, g_max_wsa_with_all_ext_size, &params), -kDot3Result_NullParameters);

  /*
   * params 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(g_max_wsa_with_all_ext, g_max_wsa_with_all_ext_size, NULL), -kDot3Result_NullParameters);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ParseWSA() API 호출 시 전달되는 wsa_size 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ParseWSA, CHECK_PARAM_WSA_SIZE)
{
  InitTestEnv();

  struct Dot3ParseWSAParams params;

  /*
   * 정상적인 값을 전달하면 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(g_max_wsa_with_all_ext, g_max_wsa_with_all_ext_size, &params), kDot3Result_Success);

  /*
   * 실제 길이보다 큰 값을 전달해도 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(g_max_wsa_with_all_ext, g_max_wsa_with_all_ext_size + 1, &params), kDot3Result_Success);

  /*
   * 실제 길이보다 작은 값을 전달하면 asn.1 디코딩이 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_ParseWSA(g_max_wsa_with_all_ext, g_max_wsa_with_all_ext_size - 1, &params), -kDot3Result_Asn1Decode);
  ASSERT_EQ(Dot3_ParseWSA(g_max_wsa_with_all_ext, 0, &params), -kDot3Result_Asn1Decode);

  ReleaseTestEnv();
}
