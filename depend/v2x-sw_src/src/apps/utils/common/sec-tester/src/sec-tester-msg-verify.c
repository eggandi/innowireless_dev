/** 
 * @file
 * @brief 보안 메시지 처리 성능 테스트를 구현한 파일
 * @date 2020-10-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#include "wlanaccess/wlanaccess.h"

// 유틸리티 헤더 파일
#include "sec-tester.h"


volatile unsigned int g_test_cnt = 0; ///< 테스트 카운트
uint64_t g_start_usec;
uint64_t g_end_usec;
uint64_t g_msg_1_start_usec;
uint64_t g_msg_2_start_usec;
uint64_t g_msg_3_start_usec;
uint64_t g_msg_1_end_usec;
uint64_t g_msg_2_end_usec;
uint64_t g_msg_3_end_usec;
bool g_error = false;


/**
 * @brief SPDU 처리 콜백함수. dot2 라이브러리에서 호출된다.
 * @param[in] result 처리결과
 * @param[in] priv 패킷파싱데이터
 */
void SEC_TESTER_ProcessSPDUCallback(Dot2ResultCode result, void *priv)
{
  (void)priv;

  /*
   * 에러가 발생한 상태이면 더이상 수행하지 않는다.
   */
  if (g_error == true) {
    goto out;
  }

  /*
   * Single 모드 테스트 결과 출력
   */
  if (g_mode == kMode_Single) {
    if (result == kDot2Result_Success) {
      g_test_cnt++;
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      if (g_test_cnt == 1) { // 첫번째 메시지 처리 시간 계산
        g_msg_1_end_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
      } else if (g_test_cnt == 2) { // 두번째 메시지 처리 시간 계산
        g_msg_2_end_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
      } else { // 세번째 메시지 처리 시간 계산
        g_msg_3_end_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
        printf("[TEST] [SUCCESS]\n");
        printf("       [1] 1st SPDU(cert-signed)   processing latency : %5"PRIu64" usec (public key reconstruction & sign verification)\n", g_msg_1_end_usec - g_msg_1_start_usec);
        printf("       [2] 2nd SPDU(cert-signed)   processing latency : %5"PRIu64" usec (sign verification)\n", g_msg_2_end_usec - g_msg_2_start_usec);
        printf("       [3] 3rd SPDU(digest-signed) processing latency : %5"PRIu64" usec (sign verification)\n", g_msg_3_end_usec - g_msg_3_start_usec);
        printf("[TEST] [END]\n");
      }
    } else {
      printf("[TEST] [FAIL] Fail to process SPDU - ret: %d. Test cannot be performed.\n", result);
      printf("[TEST] [END]\n");
      g_error = true;
      goto out;
    }
  }

  /*
   * Burst 모드 테스트 결과 출력
   */
  else if (g_mode == kMode_Burst){
    if (result == kDot2Result_Success) {
      g_test_cnt++;
      // 중간 결과 출력
      if ((g_test_cnt != 0) && ((g_test_cnt % (BURST_MODE_TEST_CNT / 10)) == 0)) {
        printf("[TEST] %u SPDUs are processed\n", g_test_cnt);
      }
      // 최종 결과 출력
      if (g_test_cnt >= BURST_MODE_TEST_CNT) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        g_end_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
        printf("[TEST] [SUCCESS]\n"
               "       [1] Total latency   : %5.3fsec (for %u SPDUs)\n"
               "       [2] Average latency : %5.3fusec\n"
               "       [3] Hz              : %5.3f\n",
               (double)(g_end_usec - g_start_usec) / (double)1e6,
               BURST_MODE_TEST_CNT,
               (double)(g_end_usec - g_start_usec) / (double)BURST_MODE_TEST_CNT,
               (double)BURST_MODE_TEST_CNT * 1e6 / (double)(g_end_usec - g_start_usec));
        printf("[TEST] [END]\n");
      }
    } else {
      printf("[TEST] [FAIL] Fail to process SPDU - ret: %d. Test cannot be performed.\n", result);
      printf("[TEST] [END]\n");
      g_error = true;
      goto out;
    }
  }

  /*
   * Check 모드 테스트 결과 출력
   */
  else {
    g_test_cnt++;
    // 첫번째 SPDU는 정상 SPDU이므로 서명 검증이 성공해야 함.
    if (g_test_cnt == 1) {
      if (result == kDot2Result_Success) {
        printf("[TEST1] [SUCCESS] Processing result for normal SPDU is success\n");
        printf("                  SPDU process function (public key reconstruction & signature verification) is GOOD\n");
      } else {
        printf("[TEST1] [FAIL] Processing result for normal SPDU is fail - ret: %d\n", result);
        printf("               SPDU process function (public key reconstruction & signature verification) is NOT GOOD\n");
      }
    }
    // 두번째 SPDU는 변조된 SPDU이므로 서명 검증이 실패해야 함.
    else {
      if (result == -kDot2Result_SignatureVerificationFailed) {
        printf("[TEST2] [SUCCESS] Processing result for tampered SPDU is \"signature verification fail\"\n");
        printf("                  SPDU process function (signature verification) is GOOD\n");
      } else if (result == kDot2Result_Success) {
        printf("[TEST2] [FAIL] Processing result for tampered SPDU is success\n");
        printf("               SPDU process function (signature verification) is NOT GOOD\n");
      } else {
        printf("[TEST2] [FAIL] Processing result for tampered SPDU is unexpected fail(%d)\n", result);
        printf("               SPDU process function (signature verification) is NOT GOOD\n");
      }
      printf("[TEST]  [END]\n");
    }
  }

out:
  V2X_FreePacketParseData((struct V2XPacketParseData *)priv);
}


/**
 * @brief MPDU 수신처리 콜백함수. 원래 접속계층라이브러리에서 호출되지만 테스트를 위해 강제로 호출한다.
 * @param[in] mpdu 수신된 MPDU
 * @param[in] mpdu_size 수신된 MPDU의 크기
 * @param[in] rx_params 수신 파라미터 정보
 */
void
SEC_TESTER_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *rx_params)
{
  /*
   * 패킷파싱데이터를 할당한다.
   */
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(mpdu, mpdu_size, rx_params);
  if (parsed == NULL) {
    printf("Fail to V2X_AllocatePacketParseData()\n");
    return;
  }

  /*
   * WSM MPDU를 파싱한다.
   */
  int ret;
  parsed->wsdu = Dot3_ParseWSMMPDU(parsed->pkt,
                                   parsed->pkt_size,
                                   &(parsed->mac_wsm),
                                   &(parsed->wsdu_size),
                                   &(parsed->interested_psid),
                                   &ret);
  if (parsed->wsdu == NULL) {
    printf("Fail to Dot3_ParseWSMMPDU(): %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * SPDU를 처리한다 - 결과는 콜백함수를 통해 전달된다.
   */
  struct Dot2SPDUProcessParams params;
  memset(&params, 0, sizeof(params));
  params.rx_time = g_sample_rse_0_valid_start + 2ULL;
  params.rx_psid = parsed->mac_wsm.wsm.psid;
  params.rx_pos.lat = g_sample_rse_0_valid_lat;
  params.rx_pos.lon = g_sample_rse_0_valid_lon;
  ret = Dot2_ProcessSPDU(parsed->wsdu, parsed->wsdu_size, &params, parsed);
  if (ret < 0) {
    printf("Fail to Dot2_ProcessSPDU(): %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
}


/**
 * @brief 테스트용 샘플 서명 메시지를 생성한다.
 * @param[in] signer_id_type 서명자 유형
 * @param[out] mpdu_size 샘플 MPDU의 길이가 반환될 변수 포인터
 * @return 샘플 MPDU
 * @retval NULL: 실패
 */
static uint8_t * SEC_TESTER_MakeSampleSignedMessage(Dot2SignerIdType signer_id_type, size_t *mpdu_size)
{
  printf("Make sample signed message\n");

  uint8_t payload[kDot2MsgSize_Max];
  size_t payload_size = 115; // Normal BSM size

  /*
   * SPDU(IEEE 1609.2 메시지)를 생성한다.
   */
  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Signed;
  params.time = g_sample_rse_0_valid_start + 1ULL;
  params.signed_data.psid = g_sample_rse_0_psid;
  params.signed_data.signer_id_type = signer_id_type;
  params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
  params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
  params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
  res = Dot2_ConstructSPDU(&params, payload, payload_size);
  if (res.ret < 0) {
    printf("Fail to make sample digest signed message - Dot2_ConstructSPDU() failed: %d\n", res.ret);
    return NULL;
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
  int ret;
  uint8_t *mpdu = Dot3_ConstructWSMMPDU(&dot3_params, spdu, (Dot3WSMPayloadSize)spdu_size, mpdu_size, &ret);
  free(res.spdu);
  if (mpdu == NULL) {
    printf("Fail to make sample digest signed message - Dot3_ConstructWSMMPDU() failed: %d\n", ret);
    return NULL;
  }
  return mpdu;
}


/**
 * @brief 서명 메시지 처리 테스트를 수행한다.
 */
void SEC_TESTER_MsgProcessTest(void)
{
  /*
   * 테스트용 샘플 서명 메시지를 생성한다.
   */
  size_t cert_signed_mpdu_size;
  uint8_t *cert_signed_mpdu = SEC_TESTER_MakeSampleSignedMessage(kDot2SignerId_Certificate, &cert_signed_mpdu_size);
  if (cert_signed_mpdu == NULL) {
    return;
  }
  size_t digest_signed_mpdu_size;
  uint8_t *digest_signed_mpdu = SEC_TESTER_MakeSampleSignedMessage(kDot2SignerId_Digest, &digest_signed_mpdu_size);
  if (digest_signed_mpdu == NULL) {
    return;
  }

  /*
   * 테스트용 MPDU 수신 파라미터를 설정한다.
   */
  struct WalMPDURxParams rx_params;
  memset(&rx_params, 0, sizeof(rx_params));

  /*
   * Single 모드 테스트를 수행한다.
   *  - 첫번째 메시지 처리와 두번째 이후 메시지 처리 절차, 인증서 서명 메시지와 다이제스트 서명 메시지 처리 절차가
   *    일부 다르므로 3개의 메시지에 대해 테스트한다.
   *    - 첫번째 메시지(인증서 서명 메시지): 공개키 재구성 + 서명 검증 (고지연 동작이 2번 발생)
   *    - 두번째 메시지(인증서 서명 메시지): 서명 검증 (고지연 동작이 1번 발생)
   *    - 세번째 메시지(다이제스트 서명 메시지): 서명 검증 (고지연 동작이 1번 발생)
   */
  if (g_mode == kMode_Single) {
    printf("[TEST] [START] Single SPDU processing test\n");
    struct timespec ts;

    // 첫번째 메시지
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_msg_1_start_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
    SEC_TESTER_ProcessRxMPDUCallback(cert_signed_mpdu, cert_signed_mpdu_size, &rx_params);
    sleep(1); // 메시지 처리가 완료되기 충분한 시간만큼 지연

    // 두번째 메시지
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_msg_2_start_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
    SEC_TESTER_ProcessRxMPDUCallback(cert_signed_mpdu, cert_signed_mpdu_size, &rx_params);
    sleep(1); // 메시지 처리가 완료되기 충분한 시간만큼 지연

    // 세번째 메시지
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_msg_3_start_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
    SEC_TESTER_ProcessRxMPDUCallback(digest_signed_mpdu, digest_signed_mpdu_size, &rx_params);
  }
  /*
   * Burst 모드 테스트를 수행한다 - 메시지 처리 작업큐 오버플로우를 감안하여 실제 테스트 횟수보다 더 많이 시도한다.
   * - BSM profile 기준에 따라 5회당 한번은 인증서, 그 외에는 다이제스트로 서명된 메시지를 수신 처리한다.
   */
  else {
    printf("[TEST] [START] Burst SPDU processing test (%u SPDUs)\n", BURST_MODE_TEST_CNT);

    // 서명자 인증서의 공개키 재구성을 위해 1회 처리한다.
    SEC_TESTER_ProcessRxMPDUCallback(cert_signed_mpdu, cert_signed_mpdu_size, &rx_params);
    sleep(1);
    g_test_cnt--; // 콜백함수에서 증가된 값을 다시 감소시킨다.

    // 테스트 시작시점을 저장한다.
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_start_usec = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);

    // 테스트를 수행한다.
    unsigned int i;
    for (i = 0; i < BURST_MODE_TEST_CNT; i++) {
      if ((i % 5) == 0) {
        SEC_TESTER_ProcessRxMPDUCallback(cert_signed_mpdu, cert_signed_mpdu_size, &rx_params);
      } else {
        SEC_TESTER_ProcessRxMPDUCallback(digest_signed_mpdu, digest_signed_mpdu_size, &rx_params);
      }
      int cnt = i + 1;
      if ((cnt != 0) && ((cnt % (BURST_MODE_TEST_CNT/10)) == 0)) {
        printf("[TEST] %u SPDUs are delivered\n", cnt);
      }
    }
    printf("[TEST] Stop delivering(%u SPDUs are delivered). Wait result.\n", i);
  }
  free(cert_signed_mpdu);
  free(digest_signed_mpdu);
}


/**
 * @brief 샘플 서명 메시지에 대한 테스트를 수행한다.
 */
void SEC_TESTER_SampleMsgProcessTest(void)
{
  /*
   * 내용 없는 패킷파싱데이터를 할당한다. (정상 SPDU용 및 비정상 SPDU용)
   */
  struct V2XPacketParseData *parsed1 = V2X_AllocateDSRCPacketParseData(NULL, 0, NULL);
  if (parsed1 == NULL) {
    printf("Fail to V2X_AllocatePacketParseData()\n");
    return;
  }
  struct V2XPacketParseData *parsed2 = V2X_AllocateDSRCPacketParseData(NULL, 0, NULL);
  if (parsed2 == NULL) {
    printf("Fail to V2X_AllocatePacketParseData()\n");
    return;
  }

  printf("[TEST]  [START] SPDU processing check test\n");

  /*
   * 정상 SPDU를 처리한다 - 결과는 콜백함수를 통해 전달된다.
   */
  struct Dot2SPDUProcessParams params;
  memset(&params, 0, sizeof(params));
  params.rx_time = g_sample_rse_0_valid_start + 2ULL;
  params.rx_psid = g_sample_rse_0_psid;
  params.rx_pos.lat = g_sample_rse_0_valid_lat;
  params.rx_pos.lon = g_sample_rse_0_valid_lon;
  int ret = Dot2_ProcessSPDU(g_sample_spdu, g_sample_spdu_size, &params, parsed1);
  if (ret < 0) {
    printf("Fail to Dot2_ProcessSPDU() - ret: %d\n", ret);
    V2X_FreePacketParseData(parsed1);
  }

  /*
   * 비정상 SPDU를 처리한다 - 결과는 콜백함수를 통해 전달된다.
   */
  g_sample_spdu[g_sample_spdu_size - 1]++; // SPDU 변조
  ret = Dot2_ProcessSPDU(g_sample_spdu, g_sample_spdu_size, &params, parsed2);
  if (ret < 0) {
    printf("Fail to Dot2_ProcessSPDU() - ret: %d\n", ret);
    V2X_FreePacketParseData(parsed2);
  }
}
