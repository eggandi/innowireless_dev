/**
 * @file
 * @brief dot2 라이브러리의 인증서 관련 API 구현 파일
 * @date 2020-04-02
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"


/**
 * @brief Service Certificate Chain에 속한 CA인증서(rca,ica,pca/aca,eca,ra,crlg,ma)를
 *        CA인증서정보 저장소에 추가한다(상세 내용 API 매뉴얼 참조).
 * @param[in] cert 추가할 CA인증서 바이트열
 * @param[in] cert_size 추가할 CA인증서 바이트열의 길이
 * @param[in] cert_class 추가할 CA인증서의 SCC 인증서 클래스
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 추가하고자 하는 인증서를 검증할 수 있는 상위인증서가 저장소에 먼저 저장되어 있어야 한다.
 */
int OPEN_API Dot2_AddSCCCert(const uint8_t *cert, Dot2CertSize cert_size)
{
  Log(kDot2LogLevel_Event, "Add SCC cert - cert_size: %zu\n", cert_size);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (cert == NULL) {
    return -kDot2Result_NullParameters;
  }
  if (dot2_CheckCertSize(cert_size) == false) {
    return -kDot2Result_CERT_InvalidCertSize;
  }

  /*
   * 인증서정보를 추가한다.
   */
  int ret;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_AddSCCCert(cert, cert_size, &ret);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  return ret;
}


/**
 * @brief Service Certificate Chain에 속한 CA인증서(rca,ica,pca/aca,eca,ra,crlg,ma) 파일로부터
 *        인증서정보를 추출하여 CA인증서정보 저장소에 추가한다(상세 내용 API 매뉴얼 참조).
 * @param[in] file_path CA인증서 파일경로 (상대경로 or 절대경로)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 추가하고자 하는 인증서를 검증할 수 있는 상위인증서가 저장소에 먼저 저장되어 있어야 한다.
 */
int OPEN_API Dot2_LoadSCCCertFile(const char *file_path)
{
  /*
   * 파라미터 유효성을 체크한다.
   */
  if (file_path == NULL) {
    Err("Fail to load SCC cert file - null parameters\n");
    return -kDot2Result_NullParameters;
  }

  Log(kDot2LogLevel_Event, "Load SCC cert file(%s)\n", file_path);

  /*
   * 파일로부터 인증서바이트열을 획득하여 인증서정보 저장소에 추가한다.
   */
  uint8_t cert[kDot2CertSize_Max];
  int ret = dot2_ImportFile(file_path, cert, kDot2CertSize_Min, sizeof(cert));
  if (ret > 0) {
    size_t cert_size = (size_t)ret;
    ret = kDot2Result_Success;
    pthread_mutex_lock(&(g_dot2_mib.mtx));
    dot2_AddSCCCert(cert, cert_size, &ret);
    pthread_mutex_unlock(&(g_dot2_mib.mtx));
  }
  return ret;
}


/**
 * @brief 유효기간이 만료된 SCC인증서들의 정보를 SCC 인증서정보 저장소에서 제거한다(상세 내용 API 매뉴얼 참조).
 * @parma[in] exp 기준이 되는 만기시각. 0일 경우 API 내부에서 현재시각으로 설정된다.
 */
void OPEN_API Dot2_RemoveExpiredSCCCert(Dot2Time64 exp)
{
  if (exp == 0) {
    exp = dot2_GetCurrentTime64();
  }
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_RemoveExpiredSCCCert(exp);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
}


/**
 * @brief CMH 테이블 내 만기된 CMH 정보를 제거한다(상세 내용 API 매뉴얼 참조).
 * @parma[in] exp 기준이 되는 만기시각. 0일 경우 API 내부에서 현재시각으로 설정된다.
 */
void OPEN_API Dot2_RemoveExpiredCMH(Dot2Time64 exp)
{
  if (exp == 0) {
    exp = dot2_GetCurrentTime64();
  }
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_RemoveExpiredCMH(exp);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
}


/**
 * @brief 타 장치(EE) 인증서정보 캐싱테이블 내 오래된 인증서정보를 제거한다(상세 내용 API 매뉴얼 참조).
 * @parma[in] exp 기준이 되는 만기시각. 0일 경우 API 내부에서 현재시각으로 설정된다.
 */
void OPEN_API Dot2_RemoveExpiredEECertCache(Dot2Time64 exp)
{
  if (exp == 0) {
    exp = dot2_GetCurrentTime64();
  }
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_RemoveExpiredEECertCache(exp);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
}
