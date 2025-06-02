/** 
 * @file
 * @brief j29451 라이브러리 단위테스트 메인 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <assert.h>

// 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal-types.h"
#include "j29451-mib.h"
#include "j29451-test.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "test-libj29451.h"


struct J29451Test_BSMTransmitCallbackList g_bsm_callback_list;


/**
 * @brief 테스트용 GPS 데이터 정보를 초기화한다.
 */
void J29451Test_InitTestGPSData()
{
  int gps_time;
  for (int i = 0; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].fix.mode = MODE_3D;
    g_test_gps_data[i].fix.latitude = TEST_GNSS_DATA_INITIAL_LAT_RAW + (i * LAT_RAW_OFFSET);
    g_test_gps_data[i].fix.longitude = TEST_GNSS_DATA_INITIAL_LON_RAW + (i * LON_RAW_OFFSET);
    g_test_gps_data[i].fix.speed = TEST_GNSS_DATA_INITIAL_SPEED_RAW + (i * SPEED_RAW_OFFSET);
    g_test_gps_data[i].fix.track = TEST_GNSS_DATA_INITIAL_HEADING_RAW + (i * HEADING_RAW_OFFSET);
    g_test_gps_data[i].fix.altHAE = TEST_GNSS_DATA_INITIAL_ELEV_RAW + (i * ELEV_RAW_OFFSET);
    gps_time = (i * 100); // = 100 msec 마다 발생한 데이터
    g_test_gps_data[i].fix.time.tv_sec = gps_time / 1000;
    g_test_gps_data[i].fix.time.tv_nsec = (gps_time % 1000) * 1000000;
    g_test_gps_data[i].gst.smajor_deviation = TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ACCURACY_RAW + ((double)i * 0.05); // 2735에 정의된 단위값(0.05미터)씩 증가
    g_test_gps_data[i].gst.sminor_deviation = TEST_GNSS_DATA_INITIAL_SEMI_MINOR_AXIS_ACCURACY_RAW + ((double)i * 0.05); // 2735에 정의된 단위값(0.05미터)씩 증가
    g_test_gps_data[i].gst.smajor_orientation = TEST_GNSS_DATA_INITIAL_SEMI_MAJOR_AXIS_ORIENTATION_RAW + ((double)i * 0.0054932479); // 2735에 정의된 단위값(0.0054932479도)씩 증가
    g_test_gps_data[i].attitude.acc_x = TEST_GNSS_DATA_INITIAL_LAT_ACCELERATION_RAW + ((double)i * 0.01); // 2735에 정의된 단위값(0.01m/s^2)씩 증가
    g_test_gps_data[i].attitude.acc_y = TEST_GNSS_DATA_INITIAL_LON_ACCELERATION_RAW + ((double)i * 0.01); // 2735에 정의된 단위값(0.01m/s^2)씩 증가
    g_test_gps_data[i].attitude.acc_z = TEST_GNSS_DATA_INITIAL_VERT_ACCELERATION_RAW + ((double)i * 0.1962); // 2735에 정의된 단위값(0.1962m/s^2)씩 증가
    g_test_gps_data[i].attitude.gyro_z = TEST_GNSS_DATA_INITIAL_YAW_RATE_RAW + ((double)i * 0.01); // 2735에 정의된 단위값(0.01도/s)씩 증가
  }
  g_test_gps_data_idx = -1;
}


/**
 * @brief BSM 송신 콜백 리스트를 비운다.
 */
static void J29451Test_FlushBSMTransmitCallbackList()
{
  struct J29451Test_BSMTransmitCallbackListEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(g_bsm_callback_list.head), entries, tmp) {
    TAILQ_REMOVE(&(g_bsm_callback_list.head), entry, entries);
    free(entry);
  }
  g_bsm_callback_list.entry_num = 0;
}


/**
 * @brief j29451 라이브러리로부터 BSM 송신 요청을 수신하여 처리하는 콜백함수. j29451 라이브러리에서 호출된다.
 * @param[in] bsm BSM 메시지 UPER 인코딩 바이트열
 * @param[in] bsm_size BSM 메시지의 길이
 * @param[in] event 이벤트 발생 여부
 * @param[in] cert_sign 인증서로 서명해야 하는지 여부
 * @param[in] id_change ID/인증서 변경 필요 여부
 * @param[in] addr 랜덤하게 생성된 MAC 주소. id_change=true일 경우 본 MAC 주소를 장치에 설정해야 한다.
 */
void J29451Test_ProcessBSMTransmitCallback(
  const uint8_t *bsm,
  size_t bsm_size,
  bool event,
  bool cert_sign,
  bool id_change,
  uint8_t *addr)
{
  struct timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);

  struct J29451Test_BSMTransmitCallbackListEntry *entry;
  entry = (struct J29451Test_BSMTransmitCallbackListEntry *)calloc(1, sizeof(struct J29451Test_BSMTransmitCallbackListEntry));
  assert(entry != nullptr);
  entry->msec = (((uint64_t)ts.tv_sec * 1000) + ((uint64_t)ts.tv_nsec / 1000000));
  memcpy(entry->bsm, bsm, bsm_size);
  entry->bsm_size = bsm_size;
  entry->event = event;
  entry->cert_sign = cert_sign;
  entry->id_change = id_change;
  memcpy(entry->addr, addr, MAC_ALEN);
  TAILQ_INSERT_TAIL(&(g_bsm_callback_list.head), entry, entries);
  g_bsm_callback_list.entry_num++;
}


/**
 * @brief 테스트 환경을 해제한다. 매 TEST() 함수의 종료 부분에서 호출된다.
 */
void J29451Test_ReleaseEnv()
{
  J29451Test_FlushBSMTransmitCallbackList();
  J29451_Release();
}


/**
 * @brief 두 바이트열이 동일한지 비교한다.
 * @param[in] oct1 비교할 바이트열
 * @param[in] oct2 비교할 바이트열
 * @param[in] len 비교할 길이
 * @return 동일한지 여부
 */
bool J29451Test_CompareOctets(const uint8_t *oct1, const uint8_t *oct2, size_t len)
{
  return (memcmp(oct1, oct2, len) == 0);
}


/**
 * @brief 정의된 모든 단위테스트를 수행한다(테스트 시작 지점).
 */
int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
