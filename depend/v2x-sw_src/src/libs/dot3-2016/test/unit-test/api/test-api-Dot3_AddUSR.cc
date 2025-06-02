/**
 * @file
 * @brief Dot3_AddUSR() API에 대한 단위테스트 구현 파일
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
 * @brief Dot3_AddUSR() API 호출 시 필수정보가 정상적으로 등록되는 것을 확인한다.
 */
TEST(Dot3_AddUSR, MANDATORY_PARAMS)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR의 필수정보를 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);

  /*
   * API 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);

  /*
   * 등록된 USR을 확인한다.
   */
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);

  /*
   * 샘플 USR과 반환된 USR 정보를 비교한다.
   */
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 옵션정보가 정상적으로 등록되는 것을 확인한다.
 */
TEST(Dot3_AddUSR, OPTIONAL_PARAMS)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;


  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * API 호출 시 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);

  /*
   * 등록된 USR을 확인한다.
   */
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);

  /*
   * 샘플 USR과 반환된 USR 정보를 비교한다.
   */
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 NULL 파라미터 전달에 대한 동작을 확인한다.
 */
TEST(Dot3_AddUSR, CHECK_PARAM_NULL_PSR)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;


  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * API 호출 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddUSR(NULL), -kDot3Result_NullParameters);
  ASSERT_EQ(Dot3_GetUSRNum(), 0UL);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 전달되는 PSID 값에 따른 동작을 확인한다.
 */
TEST(Dot3_AddUSR, CHECK_MANDATORY_PARAM_PSID)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * 최소값(kDot3PSID_Min)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = psid = kDot3PSID_Min;
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 최대값(kDot3PSID_Max)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = psid = kDot3PSID_Max;
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 유효하지 않은 값(kDot3PSID_Max+1)을 전달하는 경우 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = psid = kDot3PSID_Max + 1;
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_InvalidPSID);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 전달되는 WSA type 값에 따른 동작을 확인한다.
 */
TEST(Dot3_AddUSR, CHECK_MANDATORY_PARAM_WSA_TYPE)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * 최소값(kDot3WSAType_Min)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  SetUSRMandatoryInfo(++psid, kDot3WSAType_Min, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 최대값(kDot3WSAType_Max)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  SetUSRMandatoryInfo(++psid, kDot3WSAType_Max, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 최소값보다 작은 값(kDot3WSAType_Min - 1)을 전달하는 경우 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  SetUSRMandatoryInfo(++psid, kDot3WSAType_Min - 1, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_InvalidWSAType);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), -kDot3Result_NoSuchUSR);

  /*
   * 최대값보다 작은 값(kDot3WSAType_Max + 1)을 전달하는 경우 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  SetUSRMandatoryInfo(++psid, kDot3WSAType_Max + 1, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_InvalidWSAType);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), -kDot3Result_NoSuchUSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 전달되는 PSC 값에 따른 동작을 확인한다.
 */
TEST(Dot3_AddUSR, CHECK_OPTIONAL_PARAM_PSC)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * PSC를 전달하지 않아도 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  usr.present.psc = false;
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 최소길이(kDot3PSCLen_Min=0)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalPSC("", &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));
  ASSERT_EQ(usr_r.psc.len, kDot3PSCLen_Min);

  /*
   * 최대길이(kDot3PSCLen_Max=31)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalPSC("0123456789012345678901234567890", &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));
  ASSERT_EQ(usr_r.psc.len, kDot3PSCLen_Max);

  /*
   * 유효하지 않은 길이(kDot3PSCLen_Max+1)을 전달하는 경우 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  usr.psc.len = kDot3PSCLen_Max + 1;
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_InvalidPSCLen);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), -kDot3Result_NoSuchUSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 전달되는 Source MAC address 값에 따른 동작을 확인한다.
 */
TEST(Dot3_AddUSR, CHECK_OPTIONAL_PARAM_SRC_MAC_ADDRESS)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * Source MAC address 를 전달하지 않아도 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  usr.present.src_mac_addr = false;
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 전달된 MAC 주소가 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 전달되는 Advertiser ID 값에 따른 동작을 확인한다.
 */
TEST(Dot3_AddUSR, CHECK_OPTIONAL_PARAM_ADVERTISER_ID)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * Advertiser ID를 전달하지 않아도 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  usr.present.advertiser_id = false;
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 최소길이(kDot3WSAAdvertiserIDLen_Min=0)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalAdvertiserID("1", &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));
  ASSERT_EQ(usr_r.advertiser_id.len, kDot3WSAAdvertiserIDLen_Min);

  /*
   * 최대길이(kDot3WSAAdvertiserIDLen_Max=32)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalAdvertiserID("01234567890123456789012345678901", &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));
  ASSERT_EQ(usr_r.advertiser_id.len, kDot3WSAAdvertiserIDLen_Max);

  /*
   * 최소길이보다 작은 값(kDot3WSAAdvertiserIDLen_Min-1)을 전달하는 경우 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  usr.advertiser_id.len = kDot3WSAAdvertiserIDLen_Min - 1;
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_InvalidAdvertiserIDLen);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), -kDot3Result_NoSuchUSR);

  /*
   * 최대길이보다 큰 값(kDot3WSAAdvertiserIDLen_Max+1)을 전달하는 경우 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  usr.advertiser_id.len = kDot3WSAAdvertiserIDLen_Max + 1;
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_InvalidAdvertiserIDLen);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), -kDot3Result_NoSuchUSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 전달되는 Channel Number 값에 따른 동작을 확인한다.
 */
TEST(Dot3_AddUSR, CHECK_OPTIONAL_PARAM_CHAN_NUM)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * Channel Number를 전달하지 않아도 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  usr.present.chan_num = false;
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 최소채널번호(kDot3ChannelNumber_Min)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalChannelNumber(kDot3ChannelNumber_Min, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 최대채널번호(kDot3ChannelNumber_Max)을 전달하는 경우 정상 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalChannelNumber(kDot3ChannelNumber_Max, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 유효하지 않은 채널번호(kDot3ChannelNumber_Max+1)을 전달하는 경우 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  SetUSROptionalChannelNumber(kDot3ChannelNumber_Max + 1, &usr);
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_InvalidChannelNumber);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), -kDot3Result_NoSuchUSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 이미 등록된 PSID에 대해 등록하면 실패하는 것을 확인한다.
 */
TEST(Dot3_AddUSR, DUPLICATE_PSID)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * USR을 등록하면 정상적으로 등록되는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(Dot3USR));
  usr.psid = ++psid;
  ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  /*
   * 동일한 PSID를 갖는 USR을 등록하면 실패하는 것을 확인한다(기존 USR은 유지되는 것을 확인한다)
   */
  memset(&usr_r, 0, sizeof(usr_r));
  Dot3USR usr2;
  SetUSRMandatoryInfo(psid, wsa_type, &usr2);
  ASSERT_EQ(Dot3_AddUSR(&usr2), -kDot3Result_DuplicatedUSR);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
  ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
  ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddUSR() API 호출 시 테이블이 가득 차 있으면 실패하는 것을 확인한다.
 */
TEST(Dot3_AddUSR, TABLE_FULL)
{
  InitTestEnv();

  Dot3USRNum usr_num = 0;
  Dot3USR usr, usr_r;
  Dot3PSID psid = 0;
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3MACAddress src_mac_addr = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  Dot3ChannelNumber chan_num = 178;

  /*
   * 등록할 USR을 세팅한다.
   */
  SetUSRMandatoryInfo(psid, wsa_type, &usr);
  SetUSROptionalPSC("test", &usr);
  SetUSROptionalSourceMACAddress(src_mac_addr, &usr);
  SetUSROptionalAdvertiserID("advertiser_id1", &usr);
  SetUSROptionalChannelNumber(chan_num, &usr);

  /*
   * USR을 최대 개수만큼 등록한다.
   */
  for (unsigned int i = 0; i < kDot3USRNum_Max; i++) {
    memset(&usr_r, 0, sizeof(Dot3USR));
    usr.psid = ++psid;
    ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
    ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
    ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), kDot3Result_Success);
    ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
    ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));
  }
  ASSERT_EQ(Dot3_GetUSRNum(), kDot3USRNum_Max);

  /*
   * USR을 추가 등록하면 실패하는 것을 확인한다.
   */
  memset(&usr_r, 0, sizeof(usr_r));
  usr.psid = ++psid;
  ASSERT_EQ(Dot3_AddUSR(&usr), -kDot3Result_USRTableFull);
  ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
  ASSERT_EQ(Dot3_GetUSRWithPSID(psid, &usr_r), -kDot3Result_NoSuchUSR);

  ReleaseTestEnv();
}
