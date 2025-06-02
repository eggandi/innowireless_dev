/** 
  * @file 
  * @brief 난수 생성 관련 기능을 구현한 파일
  * @date 2021-09-15 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief 난수생성기가 사용가능한지 체크한다.
 * @param[in] rng_dev 난수생성기 이름
 * @retval 0: 사용 가능함
 * @retval 음수(-Dot2ResultCode): 사용 가능하지 않음
 */
static int dot2_CheckRandomNumberGeneratorAvailable(const char *rng_dev)
{
  int ret = -kDot2Result_NoSuchDevice;
  int fd = open(rng_dev, O_RDONLY);
  if (fd != -1) {
    close(fd);
    ret = kDot2Result_Success;
  }
  return ret;
}


/**
 * @brief 난수생성기 정보를 설정한다.
 * @param[in] rng_dev 어플리케이션이 전달한 난수생성기 이름 (NULL 가능)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_SetRandomNumberGenerator(const char *rng_dev)
{
  Log(kDot2LogLevel_Event, "Set random number generator\n");
  int ret;

  /*
   * 난수생성기 이름이 전달된 경우, 해당 난수생성기의 이름을 MIB에 저장하고 사용 가능한지 확인한다.
   */
  if (rng_dev) {
    // 이름 저장
    size_t len = strlen(rng_dev);
    if (len > sizeof(g_dot2_mib.rng_dev.name) - 1) {
      Err("Fail to set random number generator - too long name %zu\n", len);
      return -kDot2Result_TooLongRandomNumberGeneratorName;
    }
    memcpy(g_dot2_mib.rng_dev.name, rng_dev, len);

    // 해당 난수생성기가 사용 가능한지 확인
    ret = dot2_CheckRandomNumberGeneratorAvailable(g_dot2_mib.rng_dev.name);
    if (ret < 0) {
      Err("Fail to set random number generator(%s) - unavailable\n", g_dot2_mib.rng_dev.name);
      return ret;
    }
    g_dot2_mib.rng_dev.use = true;
    Log(kDot2LogLevel_Event, "Success to set random number generator(%s)\n", g_dot2_mib.rng_dev.name);
  }

  /*
   * 난수생성기 이름이 전달되지 않은 경우, random() 함수가 사용되도록 한다.
   */
  else {
    g_dot2_mib.rng_dev.use = false;
    Log(kDot2LogLevel_Event, "Random number generator is not specified. random() function will be used\n");
  }

  return kDot2Result_Success;
}


/**
 * @brief 랜덤값을 구한다.
 * @param[in] rng_dev 난수생성장기 이름
 * @return 랜덤값
 *
 * 랜덤디바이스로부터 값을 읽는데 실패하면 초기화되지 않은 메모리값을 리턴한다.
 */
uint8_t INTERNAL dot2_GetRandomOct(const char *rng_dev)
{
  uint8_t oct;
  if (rng_dev) {
    int fd = open(rng_dev, O_RDONLY);
    if (fd != -1) {
      read(fd, &oct, 1);
      close(fd);
    }
  }
  return oct;
}
