/** 
 * @file
 * @brief 파일 처리 관련 기능 구현 파일
 * @date 2020-05-27
 * @author gyun
 */

// 시스템 헤더 파일
#include <sys/stat.h>
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief 파일의 내용을 읽어 버퍼에 저장한 후 반환한다.
 * @param[in] file_path 파일 경로
 * @param[out] buf 파일내용이 저장될 버퍼 포인터
 * @param[in] min_size buf 버퍼에 저장 가능한 최소 길이
 * @param[in] max_size buf 버퍼에 저장 가능한 최대 길이
 * @return 버퍼에 저장된 파일내용의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ImportFile(const char *file_path, uint8_t *buf, size_t min_size, size_t max_size)
{
  Log(kDot2LogLevel_Event, "Import file(%s)\n", file_path);

  FILE *fp = NULL;
  int fd;
  struct stat s;
  size_t file_size;

  /*
   * 파일을 열고 길이를 구한다.
   */
  int ret = -kDot2Result_FILE_Access;
  if ((fp = fopen(file_path, "r")) &&
      ((fd = fileno(fp)) != -1) &&
      (fstat(fd, &s) == 0) &&
      (S_ISREG(s.st_mode))) {
    ret = kDot2Result_Success;
    file_size = (size_t)(s.st_size);
    if ((file_size < min_size) ||
        (file_size > max_size)) {
      ret = -kDot2Result_FILE_InvalidLength;
    }
  }

  if (ret == kDot2Result_Success) {
    ret = -kDot2Result_FILE_Read;
    if (fread(buf, 1, file_size, fp) == file_size) {
      ret = (int)file_size;
    }
  }

  if (fp) { fclose(fp); }
  return ret;
}


/**
 * @brief 파일의 내용을 읽어 버퍼를 생성한 후 반환한다.
 * @param[in] file_path 파일 경로
 * @param[out] buf 파일내용이 저장될 버퍼 포인터
 * @param[in] min_size buf 버퍼에 저장 가능한 최소 길이
 * @param[in] max_size buf 버퍼에 저장 가능한 최대 길이
 * @return 버퍼에 저장된 파일내용의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ImportFile_2(const char *file_path, uint8_t **buf, size_t min_size, size_t max_size)
{
  FILE *fp = NULL;
  int fd;
  struct stat s;
  size_t file_size;

  /*
   * 파일을 열고 길이를 구한다.
   */
  int ret = -kDot2Result_FILE_Access;
  if ((fp = fopen(file_path, "r")) &&
      ((fd = fileno(fp)) != -1) &&
      (fstat(fd, &s) == 0) &&
      (S_ISREG(s.st_mode))) {
    ret = kDot2Result_Success;
    file_size = (size_t)(s.st_size);
    if ((file_size < min_size) ||
        (file_size > max_size)) {
      ret = -kDot2Result_FILE_InvalidLength;
    }
  }

  /*
   * 버퍼를 할당하여 파일 내용을 저장한다.
   */
  if (ret == kDot2Result_Success) {
    ret = -kDot2Result_NoMemory;
    *buf = malloc(file_size);
    if (*buf) {
      ret = -kDot2Result_FILE_Read;
      if (fread(*buf, 1, file_size, fp) == file_size) {
        ret = (int)file_size;
      }
    }
  }

  if (fp) { fclose(fp); }
  return ret;
}


/**
 * @brief 특정 바이트열을 특정 파일경로에 저장한다.
 * @param[in] file_path 저장할 파일경로
 * @param[in] octs 저장할 바이트열
 * @param[in] len 저장할 바이트열의 길이
 * @retval 0: 성공
 * @retval -1: 실패
 */
int INTERNAL dot2_ExportFile(const char *file_path, const uint8_t *octs, size_t len)
{
  Log(kDot2LogLevel_Event, "Export file(%s)\n", file_path);

  /*
   * 파일에 저장한다.
   */
  int ret = -kDot2Result_FILE_Access;
  FILE *fp = fopen(file_path, "w");
  if (fp) {
    fwrite(octs, 1, len, fp);
    fclose(fp);
    ret = kDot2Result_Success;
  }
  return ret;
}
