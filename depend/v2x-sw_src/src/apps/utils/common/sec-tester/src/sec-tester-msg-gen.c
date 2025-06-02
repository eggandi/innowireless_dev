/** 
 * @file
 * @brief 서명 메시지 생성 성능 테스트
 * @date 2020-10-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <inttypes.h>
#include <stdio.h>
#include <time.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"

// 유틸리티 헤더 파일
#include "sec-tester.h"


/**
 * @brief 서명 메시지 생성 테스트를 수행한다.
 */
void SEC_TESTER_MsgGenerateTest(void)
{
  int test_cnt;
  if (g_mode == kMode_Single) {
    test_cnt = 1;
    printf("[TEST] [START] Single SPDU generation test\n");
  } else {
    test_cnt = BURST_MODE_TEST_CNT;
    printf("[TEST] [START] Burst SPDU generation test (%u SPDUs)\n", test_cnt);
  }

  /*
   * 테스트 시작 시점을 저장한다.
   */
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t start_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);

  /*
   * 테스트 횟수만큼 메시지를 생성한다.
   */
  for (int i = 0; i < test_cnt; i++) {

    uint8_t payload[kDot2MsgSize_Max];
    size_t payload_size = 152; // Normal BSM size (PSID는 WSA(135)이지만, 페이로드는 그냥 BSM인 걸로 한다)

    /*
     * SPDU(IEEE 1609.2 메시지)를 생성한다.
     */
    struct Dot2SPDUConstructParams params;
    struct Dot2SPDUConstructResult res;
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = g_sample_rse_0_valid_start + 1ULL;
    params.signed_data.psid = g_sample_rse_0_psid;
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
    params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
    params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
    res = Dot2_ConstructSPDU(&params, payload, payload_size);
    if (res.ret < 0) {
      printf("[TEST] [FAIL] Fail to generate SPDU - Dot2_ConstructSPDU() failed: %d\n", res.ret);
      printf("[TEST] [END]\n");
    }
    uint8_t *spdu = res.spdu;
    size_t spdu_size = res.ret;

    /*
     * WSM MPDU를 생성한다.
     *  - 실제 전송하지 않으므로 임의의 파라미터를 전달한다.
     */
    struct Dot3MACAndWSMConstructParams dot3_params;
    memset(&dot3_params, 0, sizeof(dot3_params));
    dot3_params.wsm.chan_num = 172U;
    dot3_params.wsm.datarate = 12;
    dot3_params.wsm.transmit_power = 20;
    dot3_params.mac.priority = 0;
    dot3_params.wsm.psid = g_sample_rse_0_psid;
    memset(dot3_params.mac.dst_mac_addr, 0xff, MAC_ALEN);
    memset(dot3_params.mac.src_mac_addr, 0x00, MAC_ALEN);
    size_t mpdu_size;
    int ret;
    uint8_t *mpdu = Dot3_ConstructWSMMPDU(&dot3_params, spdu, (Dot3WSMPayloadSize)spdu_size, &mpdu_size, &ret);
    free(res.spdu);
    if (mpdu == NULL) {
      printf("[TEST] [FAIL] Fail to transmit SPDU - Dot3_ConstructWSMMPDU() failed: %d\n", ret);
      printf("[TEST] [END]\n");
      return;
    }
    free(mpdu);

    // 중간 결과 출력
    int cnt = i + 1;
    if ((cnt != 0) && ((cnt % (BURST_MODE_TEST_CNT / 10)) == 0)) {
      printf("[TEST] %u SPDUs are generated\n", cnt);
    }
  }

  /*
   * 테스트에 소요된 시간을 출력한다.
   */
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t end_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
  if (g_mode == kMode_Single) {
    printf("[TEST] [SUCCESS] Single SPDU generation latency : %"PRIu64" usec\n", end_usec - start_usec);
  } else {
    printf("[TEST] [SUCCESS] Burst SPDU generation result\n"
           "       [1] Total latency   : %5.3fsec (for %u SPDUs)\n"
           "       [2] Average latency : %5.3fusec\n"
           "       [3] Hz              : %5.3f\n",
           (double)(end_usec - start_usec) / (double)1e6,
           BURST_MODE_TEST_CNT,
           (double)(end_usec - start_usec) / (double)BURST_MODE_TEST_CNT,
           (double)BURST_MODE_TEST_CNT * 1e6 / (double)(end_usec - start_usec));
  }
  printf("[TEST] [END]\n");
}
