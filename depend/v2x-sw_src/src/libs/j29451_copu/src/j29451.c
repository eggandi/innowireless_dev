/** 
 * @file
 * @brief j29451 라이브러리 메인 구현 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 라이브러리 의존 헤더 파일
#ifdef _CRATON2_
#include "atlk/rng.h"
#endif

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"


/// 라이브러리 MIB
struct J29451MIB g_j29451_mib;


/**
 * @brief 라이브러리 기능을 초기화한다.
 * @param[in] mib 라이브러리 MIB
 * @param[out] addr 랜덤하게 생성된 MAC주소가 저장될 버퍼
 */
int INTERNAL j29451_Init(struct J29451MIB *mib, uint8_t *addr)
{
  Log(kJ29451LogLevel_Event, "Initialize library function\n");
  memset(mib, 0, sizeof(struct J29451MIB));
  pthread_mutex_init(&(mib->mtx), NULL);

#ifdef _CRATON2_
  /*
   * Random 값 사용을 위해 ehsm을 초기화한다.
   */
  atlk_rc_t rc = ehsm_service_get(NULL, &(g_j29451_mib.ehm_service));
  if (atlk_error(rc)) {
    Err("Fail to initialize library function - ehsm_service_get() failed: %s\n", atlk_rc_to_str(rc));
    return -kJ29451Result_Unspecified;
  }
#endif

  j29451_InitVehicleInfo(&(mib->vehicle));
  j29451_InitBSMData(&(mib->bsm_data), addr);
  j29451_InitBSMTx(&(mib->bsm_tx));
  j29451_InitPathInfo(&(mib->path));
  return j29451_InitOBUInfo(&(mib->obu));
}


/**
 * @brief 라이브러리 기능을 종료하고 정보를 해제한다.
 * @param[in] mib 라이브러리 MIB
 */
void INTERNAL j29451_Release(struct J29451MIB *mib)
{
  j29451_ReleaseBSMTransmit(&(mib->bsm_tx));
  j29451_ReleaseBSMData(&(mib->bsm_data));
  j29451_ReleaseVehicleInfo(&(mib->vehicle));
  j29451_ReleaseOBUInfo(&(mib->obu));
  j29451_ReleasePathInfo(&(mib->path));
}


/**
 * @brief 랜덤값을 갖는 바이트열을 구한다.
 * @param[out] r 랜덤값이 저장될 버퍼
 * @param[in] size r 버퍼의 길이
 */
void INTERNAL j29451_GetRandomOcts(uint8_t *r, size_t size)
{
#ifdef _CRATON2_
#if 1
  atlk_rc_t rc = ehsm_rng_generate(g_j29451_mib.ehm_service, 1, r, size);
  if (atlk_error(rc)) {
    Err("Fail to get random octs fill all 1 - ehsm_rng_generate() failed: %s\n", atlk_rc_to_str(rc));
    memset(r, 0xff, size);
  }
#else
  atlk_rc_t rc = rng_data_get(r, size);
  if (rc != ATLK_OK) {
    memset(r, 0xff, size);
  }
#endif
#else
  int fd = open("/dev/random", O_RDONLY);
  if (fd != -1) {
    read(fd, r, size);
    close(fd);
  }
#endif
}
