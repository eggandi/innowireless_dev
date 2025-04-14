/** 
 * @file
 * @brief 파일 import 기능 구현 파일
 * @date 2020-05-23
 * @author gyun
 */

// 시스템 헤더 파일
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// 내부 헤더 파일
#include "cmhf.h"


/**
 * @brief 인증서파일의 내용을 import하여 저장한다.
 * @param[in] file_path 인증서파일 경로
 * @param[out] cert_buf 인증서데이터가 저장될 버퍼
 * @param[in] cert_buf_size cert_buf 버퍼의 크기
 * @return 저장된 인증서 바이트열의 크기
 * @retval -1: 실패
 */
int CMHF_ImportCertFile(const char *file_path, uint8_t *cert_buf, size_t cert_buf_size)
{
  if (g_dbg == true) {
    printf("Import certificate file(%s)\n", file_path);
  }

  /*
   * 파일 데이터의 길이를 구한다.
   */
  struct stat s;
  int ret = stat(file_path, &s);
  if (ret < 0) {
    printf("Fail to import certificate file(%s) - stat() failed : %m\n", file_path);
    return -1;
  }
  if ((size_t)(s.st_size) > cert_buf_size) {
    printf("Fail to import certificate file(%s) - too long file : %ld > %zu\n", file_path, s.st_size, cert_buf_size);
    return -1;
  }

  /*
   * 파일로부터 데이터를 읽어 들인다.
   */
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    printf("Fail to import certificate file(%s) - fopen() failed : %m\n", file_path);
    return -1;
  }
  fread(cert_buf, s.st_size, 1, fp);
  fclose(fp);

  if (g_dbg == true) {
    CMHF_PrintOctets("Success to import :", cert_buf, s.st_size);
  }

  return s.st_size;
}


/**
 * @brief 개인키 등(개인키, 개인키 재구성값, 인증서요청 개인키) 파일의 내용을 import하여 저장한다.
 * @param[in] file_path 개인키 등 파일 경로
 * @param[out] priv_key 개인키 등이 저장될 버퍼
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CMHF_ImportPrivateKey(const char *file_path, uint8_t *priv_key)
{
  if (g_dbg == true) {
    printf("Import priv key related file(%s)\n", file_path);
  }

  /*
   * 파일 데이터의 길이를 구한다.
   */
  struct stat s;
  int ret = stat(file_path, &s);
  if (ret < 0) {
    printf("Fail to import priv key related file(%s) - stat() failed : %m\n", file_path);
    return -1;
  }
  if ((size_t)(s.st_size) > DOT2_EC_256_KEY_LEN) {
    printf("Fail to import priv key related file(%s) - too long file(%ld > %u)\n",
      file_path, s.st_size, DOT2_EC_256_KEY_LEN);
    return -1;
  }

  /*
   * 파일 데이터의 길이가 개인키의 길이인 32바이트에 못 미치는 경우,
   * 이는 앞의 0x00(들)이 생략되었다고 볼 수 있다. 이 경우 비어 잇는 곳에 0x00을 채워주고 그 다음부터 저장하도록 한다.
   */
  memset(priv_key, 0, DOT2_EC_256_KEY_LEN);
  uint8_t *ptr = priv_key;
  if (s.st_size < DOT2_EC_256_KEY_LEN) {
    unsigned int shortage = DOT2_EC_256_KEY_LEN - s.st_size;
    ptr += shortage;
  }

  /*
   * 파일로부터 데이터를 읽어 들인다.
   */
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    printf("Fail to import priv key related file(%s) - fopen() failed : %m\n", file_path);
    return -1;
  }
  fread(ptr, s.st_size, 1, fp);
  fclose(fp);

  if (g_dbg == true) {
    CMHF_PrintOctets("Success to import :", priv_key, s.st_size);
  }

  return 0;
}


/**
 * @brief 키 확장용 키 파일의 내용을 import하여 저장한다.
 * @param[in] file_path 확장키 파일 경로
 * @param[out] exp_key 확장키 저장될 버퍼
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CMHF_ImportExpansionKey(const char *file_path, uint8_t *exp_key)
{
  if (g_dbg == true) {
    printf("Import expansion key file(%s)\n", file_path);
  }

  /*
   * 파일 데이터의 길이를 구한다.
   */
  struct stat s;
  int ret = stat(file_path, &s);
  if (ret < 0) {
    printf("Fail to import expansion key file(%s) - stat() failed : %m\n", file_path);
    return -1;
  }
  if ((size_t)(s.st_size) >  DOT2_AES_128_LEN) {
    printf("Fail to import expansion key file(%s) - too long file(%ld > %u)\n", file_path, s.st_size, DOT2_AES_128_LEN);
    return -1;
  }

  /*
   * 파일 데이터의 길이가 확장키의 길이인 16바이트에 못 미치는 경우,
   * 이는 앞의 0x00(들)이 생략되었다고 볼 수 있다. 이 경우 비어 잇는 곳에 0x00을 채워주고 그 다음부터 저장하도록 한다.
   */
  memset(exp_key, 0, DOT2_AES_128_LEN);
  uint8_t *ptr = exp_key;
  if (s.st_size < DOT2_AES_128_LEN) {
    unsigned int shortage = DOT2_AES_128_LEN - s.st_size;
    ptr += shortage;
  }

  /*
   * 파일로부터 데이터를 읽어 들인다.
   */
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    printf("Fail to import expansion key file(%s) - fopen() failed : %m\n", file_path);
    return -1;
  }
  fread(ptr, s.st_size, 1, fp);
  fclose(fp);

  if (g_dbg == true) {
    CMHF_PrintOctets("Success to import :", exp_key, s.st_size);
  }

  return 0;
}
