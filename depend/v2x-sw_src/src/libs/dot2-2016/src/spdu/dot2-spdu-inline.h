/** 
  * @file 
  * @brief SPDU 관련 인라인함수 정의
  * @date 2021-09-04 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_SPDU_INLINE_H
#define V2X_SW_DOT2_SPDU_INLINE_H


// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "certificate/cert-info/dot2-cert-info-inline.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief SPDU 생성 유형의 유효성을 체크한다.
 * @param[in] type 유효성을 체크할 SPDU 생성 유형
 * @return 유효한지 여부
 */
static inline bool dot2_CheckSPDUConstructType(Dot2SPDUConstructType type)
{
  return (type <= kDot2SPDUConstructType_Max) ? true : false;
}

/**
 * @brief SPDU 생성에 사용되는 서명자인증서 식별자 유형의 유효성을 체크한다.
 * @param[in] type 유효성을 체크할 서명자인증서 식별자 유형
 * @return 유효한지 여부
 */
static inline bool dot2_CheckSPDUConstructSignerIdType(Dot2SignerIdType type)
{
  if ((type == kDot2SignerId_Profile) ||
      (type == kDot2SignerId_Digest) ||
      (type == kDot2SignerId_Certificate)) {
    return true;
  }
  return false;
}


/**
 * @brief 위도값의 유효성을 체크한다.
 * @param[in] lat 유효성을 체크할 위도값
 * @return 유효한지 여부
 */
static inline bool dot2_CheckLatitude(Dot2Latitude lat)
{
  if (((lat >= kDot2Latitude_Min) && (lat <= kDot2Latitude_Max)) || // 범위 내이거나
      (lat == kDot2Latitude_Unavailable)) { // Unavailable 이거나
    return true;
  }
  return false;
}


/**
 * @brief 경도값의 유효성을 체크한다.
 * @param[in] lon 유효성을 체크할 경도값
 * @return 유효한지 여부
 */
static inline bool dot2_CheckLongitude(Dot2Longitude lon)
{
  if (((lon >= kDot2Longitude_Min) && (lon <= kDot2Longitude_Max)) || // 범위 내이거나
      (lon == kDot2Longitude_Unavailable)) { // Unavailable 이거나
    return true;
  }
  return false;
}


/**
 * @brief 2DLocation 정보의 유효성을 체크한다.
 * @param[in] location 유효성을 체크할 2DLocation 정보
 * @return 유효한지 여부
 */
static inline bool dot2_CheckTwoDLocation(const struct Dot2TwoDLocation *location)
{
  if (dot2_CheckLatitude(location->lat) &&
      dot2_CheckLongitude(location->lon)) {
    return true;
  }
  return false;
}


/**
 * @brief 3DLocation 정보의 유효성을 체크한다.
 * @param[in] location 유효성을 체크할 3DLocation 정보
 * @return 유효한지 여부
 */
static inline bool dot2_CheckThreeDLocation(const struct Dot2ThreeDLocation *location)
{
  if (dot2_CheckLatitude(location->lat) &&
      dot2_CheckLongitude(location->lon)) { // Elevation은 uint16_t 내 모든 값을 다 사용할 수 있으므로, 유효성체크가 무의미하다.
    return true;
  }
  return false;
}


/**
 * @brief SPDU에 수납되는 페이로드 길이의 유효성을 체크한다.
 * @param[in] payload_size 유효성을 체크할 페이로드의 길이
 * @return 유효한지 여부
 *
 * 생성되는 SPDU의 헤더 내용에 따라 페이로드 최대 길이는 달라질 수 있으므로, 여기서는 SPDU의 헤더 길이가 최소인 경우에 가능한 페이로드의
 * 최대 길이를 기준으로 체크한다. 본 체크를 통과하더라도, 실제 SPDU가 생성되면서 허용되는 페이로드의 최대길이가 줄어들어 SPDU 생성이
 * 실패할 수 있다.
 */
static inline bool dot2_CheckSPDUPayloadSize(Dot2SPDUSize payload_size)
{
  return (payload_size <= kDot2SPDUSize_MaxPayload) ? true : false;
}


/**
 * @brief Unsecured SPDU를 생성한다.
 * @param[in] payload 수납될 페이로드
 * @param[in] payload_size 수납될 페이로드의 길이
 * @param[out] spdu 인코딩된 SPDU 바이트열이 저장될 버퍼 포인터
 * @return 인코딩된 SPDU 바이트열의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ConstructUnsecuredSPDU(const uint8_t *payload, Dot2SPDUSize payload_size, uint8_t **spdu)
{
  /*
   * 메시지를 인코딩한다.
   */
#if defined(_FFASN1C_)
  return dot2_ffasn1c_EncodeUnsecuredIeee1609Dot2Data(payload, payload_size, spdu);
#elif defined(_OBJASN1C_)
  return dot2_objasn1c_EncodeUnsecuredIeee1609Dot2Data(payload, payload_size, spdu);
#else
#error "3rd party asn.1 library is not defined"
#endif
}



/**
 * @brief SPDU를 처리한다. 어플리케이션이 Dot2_ProcessSPDU() API를 통해 전달한 SPDU를 처리한다.
 * @param[in] spdu 처리할 SPDU (인코딩된 Ieee1609Dot2Data)
 * @param[in] spdu_size 처리할 SPDU의 길이
 * @param[in] params SPDU 처리를 위한 파라미터
 * @param[in] parsed 패킷파싱데이터 (dot2 파싱정보가 저장된 후 콜백함수를 통해 어플리케이션으로 전달된다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 작업정보(요청) 큐에 추가한다 -> 작업정보(요청) 처리 쓰레드에서 처리된다.
 */
static inline int dot2_ProcessSPDU(
  const uint8_t *spdu,
  Dot2SPDUSize spdu_size,
  struct Dot2SPDUProcessParams *params,
  struct V2XPacketParseData *parsed)
{
  return dot2_AddNewSPDUProcessWorkRequest((uint8_t *)spdu, spdu_size, params, parsed);
}


/**
 * @brief 작업정보를 작업정보 큐에 추가한다.
 * @param[in] q 작업정보 큐
 * @param[in] work 추가할 작업정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_PushSPDUProcessWork(struct Dot2SPDUProcessWorkQueue *q, struct Dot2SPDUProcessWork *work)
{
  if (q->work_cnt >= kDot2SPDUProcessWorkNum_Max) {
    return -kDot2Result_QueueFull;
  }
  TAILQ_INSERT_TAIL(&(q->head), work, entries);
  q->work_cnt++;
  return kDot2Result_Success;
}



/**
 * @brief SPDU를 파싱하고 처리한다.
 * @param[in] work SPDU 처리 작업 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ParseAndProcessSPDU(struct Dot2SPDUProcessWork *work)
{
#if defined(_FFASN1C_)
  return dot2_ffasn1c_ParseAndProcessSPDU(work);
#elif defined(_OBJASN1C_)
  return dot2_objasn1c_ParseAndProcessSPDU(work);
#else
#error "3rd party asn.1 library is not defined"
#endif
}



/**
 * @brief 작업정보를 제거한다.
 * @param[in] work 제거할 작업정보
 */
static inline void dot2_FreeSPDUProcessWork(struct Dot2SPDUProcessWork *work)
{
  if (work->data.spdu) {
    free(work->data.spdu);
  }
  dot2_FreeEECertCacheEntry(work->data.new_signer_entry);
#if defined(_SIGN_VERIFY_OPENSSL_)
  if (work->data.eck_signer_pub_key) {
    EC_KEY_free(work->data.eck_signer_pub_key);
  }
#endif
  free(work);
}


/**
 * @brief SPDU 내에 수납된 Implicit 형식 서명자인증서 내 공개키 재구성값을 이용한 공개키 재구성을 수행한다.
 * @param[in] work 작업정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ReconstructSPDUSignerPublicKey(struct Dot2SPDUProcessWork *work)
{
  /*
   * 서명자인증서 공개키 재구성을 요청한다.
   */
#if defined(_SIGN_VERIFY_OPENSSL_)
  return dot2_ossl_SignerPublicKeyReconstruction(work);
#elif defined(_SIGN_VERIFY_SAF5400_)
  int ret = dot2_saf5400_RequestSignerPublicKeyReconstruction(work);
  return ((ret < 0) ? ret : kDot2Result_SignerPublicKeyReconstructionRequested);
#elif defined(_SIGN_VERIFY_CRATON2_)
  int ret = dot2_craton2_RequestSignerPublicKeyReconstruction(work);
  return ((ret < 0) ? ret : kDot2Result_SignerPublicKeyReconstructionRequested);
#else
#error "Signature verification method is not defined"
#endif
}


/**
 * @brief SPDU 처리결과를 전달하는 어플리케이션 콜백함수를 호출한다. (SPDU 처리 결과를 어플리케이션으로 전달한다)
 * @param[in] result 처리결과
 * @param[in] parsed 패킷파싱데이터
 */
static inline void dot2_CallSPDUProcessCallback(Dot2ResultCode result, struct V2XPacketParseData *parsed)
{
  if (g_dot2_mib.spdu_process.cb) {
    g_dot2_mib.spdu_process.cb(result, parsed);
  }
}


/**
 * @brief 작업정보(결과)를 처리한다.
 * @param[in] work 작업정보(결과)
 */
static inline void dot2_ProcessSPDUProcessWorkResult(struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Process SPDU process work(result). Call application callback - result: %d\n", work->result);
  dot2_CallSPDUProcessCallback(work->result, work->data.parsed);
  dot2_FreeSPDUProcessWork(work);
}


#if defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
/**
 * @brief 작업정보를 작업정보(대기) 큐에 추가한다.
 * @param[in] spdu_process SPDU 처리기능 관리정보
 * @param[in] work 추가할 작업정보
 * @param[in] type 작업 유형
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_PushSPDUProcessWorkWait(
  struct Dot2SPDUProcess *spdu_process,
  struct Dot2SPDUProcessWork *work,
  Dot2SPDUProcessWorkType type)
{
  work->type = type;
  pthread_mutex_lock(&(spdu_process->work.wait_mtx));
  int ret = dot2_PushSPDUProcessWork(&(spdu_process->work.wait_q), work);
  if (ret < 0) {
    ret = -kDot2Result_SPDUProcessWorkWaitQueueFull;
  }
  pthread_mutex_unlock(&(spdu_process->work.wait_mtx));
  return ret;
}


/**
 * @brief 작업정보(대기)큐에 저장된 특정 작업정보를 제거한다.
 * @param[in] spdu_process SPDU 처리기능 관리정보
 * @param[in] work 제거할 작업정보 포인터
 */
static inline void dot2_RemoveSPDUProcessWorkWait(struct Dot2SPDUProcess *spdu_process, struct Dot2SPDUProcessWork *work)
{
  struct Dot2SPDUProcessWork *tmp1, *tmp2;
  pthread_mutex_lock(&(spdu_process->work.wait_mtx));
  TAILQ_FOREACH_SAFE(tmp1, &(spdu_process->work.wait_q.head), entries, tmp2) {
    if (tmp1 == work) {
      TAILQ_REMOVE(&(spdu_process->work.wait_q.head), tmp1, entries);
      spdu_process->work.wait_q.work_cnt--;
      break;
    }
  }
  pthread_mutex_unlock(&(spdu_process->work.wait_mtx));
}
#endif

#endif //V2X_SW_DOT2_SPDU_INLINE_H
