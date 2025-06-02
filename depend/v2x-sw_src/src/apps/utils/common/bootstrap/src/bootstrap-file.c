/** 
  * @file 
  * @brief 부트스트래핑 파일 관련 구현
  * @date 2022-07-17 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <sys/stat.h>
#include <stdio.h>

// 유틸리티 헤더 파일
#include "bootstrap.h"


/**
 * @brief 특정 바이트열을 파일로 저장한다.
 * @param[in] file_path 저장할 파일의 경로명
 * @param[in] octs 저장할 바이트열
 * @param[in] len 저장할 바이트열의 길이
 * @retval 0: 성공
 * @retval -1: 실패
 */
int BOOTSTARP_ExportFile(const char *file_path, const uint8_t *octs, size_t len)
{
  printf("Export file(%s)\n", file_path);

  FILE *fp = fopen(file_path, "w");
  if (!fp) {
    perror("Fail to export file : ");
    return -1;
  }
  fwrite(octs, 1, len, fp);
  fclose(fp);
  return 0;
}


/**
 * @brief 파일의 내용을 읽어 버퍼에 저장한 후 반환한다.
 * @param[in] file_path 파일 경로
 * @param[out] buf 파일내용이 저장될 버퍼 포인터
 * @param[in] min_size buf 버퍼에 저장 가능한 최소 길이
 * @param[in] max_size buf 버퍼에 저장 가능한 최대 길이
 * @return 버퍼에 저장된 파일내용의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
int BOOTSTRAP_ImportFile(const char *file_path, uint8_t *buf, size_t min_size, size_t max_size)
{
  printf("Import file(%s)\n", file_path);

  FILE *fp = NULL;
  int fd;
  struct stat s;
  size_t file_size;

  /*
   * 파일을 열고 길이를 구한다.
   */
  int ret = -1;
  if ((fp = fopen(file_path, "r")) &&
      ((fd = fileno(fp)) != -1) &&
      (fstat(fd, &s) == 0) &&
      (S_ISREG(s.st_mode))) {
    ret = 0;
    file_size = (size_t)(s.st_size);
    if ((file_size < min_size) ||
        (file_size > max_size)) {
      ret = -1;
    }
  }

  if (ret == 0) {
    ret = -1;
    if (fread(buf, 1, file_size, fp) == file_size) {
      ret = (int)file_size;
    }
  }

  if (fp) { fclose(fp); }
  return ret;
}
