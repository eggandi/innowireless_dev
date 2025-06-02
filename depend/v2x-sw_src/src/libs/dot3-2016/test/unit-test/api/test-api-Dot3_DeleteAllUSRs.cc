/**
 * @file
 * @brief Dot3_DeleteAllUSRs() API에 대한 단위테스트 구현 파일
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
 * @brief Dot3_DeleteAllUSRs() API 호출 시 모든 USR들이 정상적으로 삭제되는 것을 확인한다.
 */
TEST(Dot3_DeleteAllUSRs, NORMAL)
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
    usr.psid = psid + i;
    ASSERT_EQ(Dot3_AddUSR(&usr), (int)++usr_num);
    ASSERT_EQ(Dot3_GetUSRNum(), usr_num);
    ASSERT_EQ(Dot3_GetUSRWithPSID(psid + i, &usr_r), kDot3Result_Success);
    ASSERT_TRUE(CompareUSRMandatoryInfo(&usr, &usr_r));
    ASSERT_TRUE(CompareUSROptionalInfo(&usr, &usr_r));
  }
  ASSERT_EQ(Dot3_GetUSRNum(), kDot3USRNum_Max);

  /*
   * 모든 USR들이 정상적으로 삭제되는 것을 확인한다.
   */
  Dot3_DeleteAllUSRs();
  ASSERT_EQ(Dot3_GetUSRNum(), 0UL);

  ReleaseTestEnv();
}
