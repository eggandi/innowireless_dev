/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 공통함수 정의 파일
  * @date 2021-12-30 
  * @author gyun 
  */


// 테스트 헤더 파일
#include "test-common-funcs.h"


// 테스트 시작시간 저장 변수
struct timespec g_test_start_ts;

/**
 * @brief 두 개의 바이트열이 동일한지 비교한다.
 * @param[in] octs1 비교할 바이트열 1
 * @param[in] octs2 비교할 바이트열 2
 * @param[in] len 비교할 길이
 * @return 두 바이트열이 동일한지 여부
 */
bool Dot2Test_CompareOctets(const void *octs1, const void *octs2, size_t len)
{
  return (memcmp(octs1, octs2, len) == 0);
}



/**
 * @brief 16진수 문자열을 바이트열로 변환한다.
 * @param[in] hex_str 16진수 문자열
 * @param[out] octs 변환된 바이트열이 저장될 버퍼
 * @return 변환된 바이트열의 길이
 */
int Dot2Test_ConvertHexStrToOctets(const char *hex_str, uint8_t *octs)
{
  int i, octs_size = strlen(hex_str) / 2;
  char t[3];

  for (i = 0; i < octs_size; i++){
    memcpy(t, (hex_str + i*2), 2);
    t[2] = '\0';
    *(octs + i) = (uint8_t)strtoul(t, nullptr, 16);
  }
  return octs_size;
}



/**
 * @brief 바이트열의 내용을 화면에 출력한다.
 * @param[in] desc 바이트열 설명문
 * @param[in] octs 출력할 바이트열
 * @param[in] len 바이트열의 길이
 */
void Dot2Test_PrintOcts(const char *desc, const void *octs, size_t len)
{
  auto *ptr = (uint8_t *)octs;
  printf("%s: ", desc);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(ptr + i));
  }
  printf("\n");
}


/**
 * @brief 가변길이 랜덤 바이트열을 생성한다.
 * @param[out] buf 랜덤 바이트열이 저장될 버퍼 포인터
 * @param[in] buf_size 버퍼의 길이
 * @return 생성된 랜덤 바이트열의 길이
 */
size_t Dot2Test_GetVariableLengthRandomOcts(uint8_t *buf, size_t buf_size)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  srand(ts.tv_sec);

  size_t len = rand() % buf_size;
  for (size_t i = 0; i < len; i++) {
    *(buf + i) = (uint8_t) rand();
  }
  return len;
}


/**
 * @brief 고정길이 랜덤 바이트열을 생성한다.
 * @param[out] buf 랜덤 바이트열이 저장될 버퍼 포인터
 * @param[in] buf_size 버퍼의 길이
 */
void Dot2Test_GetFixedLengthRandomOcts(uint8_t *buf, size_t buf_size)
{
  for (size_t i = 0; i < buf_size; i++) {
    *(buf + i) = (uint8_t) rand();
  }
}


void Dot2Test_WaitSystemTimeRecovery()
{

}