/** 
  * @file 
  * @brief 
  * @date 2021-06-03 
  * @author gyun 
  */


#ifndef V2X_SW_DOT2_SPDU_H
#define V2X_SW_DOT2_SPDU_H


// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"
#if defined(_SIGN_VERIFY_SAF5400_)
#include "llc-api.h"
#endif

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"
#include "v2x-sw.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"
#include "sec-profile/dot2-sec-profile.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SPDU 처리 작업 유형
 */
enum eDot2SPDUProcessWorkType
{
  kDot2SPDUProcessWorkType_Parse, ///< SPDU 파싱 작업 (가장 처음에 수행되는 작업)
#if defined (_SIGN_VERIFY_SAF5400_)
  kDot2SPDUProcessWorkType_SignerPublicKeyReconstructionValueRecovery, ///< 서명자인증서 공개키재구성값 복구
#endif
  kDot2SPDUProcessWorkType_SignerPublicKeyReconstruction, ///< 서명자인증서 공개키재구성 작업
  kDot2SPDUProcessWorkType_SignVerification, ///< 서명검증 작업
  kDot2SPDUProcessWorkType_ApplicationCallback, ///< 어플리케이션에 전달
};
typedef unsigned int Dot2SPDUProcessWorkType; ///< @ref eDot2SPDUProcessWorkType


/**
 * @brief 작업큐 내에 저장되는 SPDU 처리작업의 개수
 */
enum eDot2SPDUProcessWorkNum
{
  kDot2SPDUProcessWorkNum_Min = 0,
  kDot2SPDUProcessWorkNum_Max = 10000000, ///< 작업큐 내에 저장 가능한 최대 작업수
#if defined(_SIGN_VERIFY_SAF5400_)
  kDot2SPDUProcessWorkNum_MaxProcessing = 16 ///< saf5400이 동시에 처리 가능한 최대 작업 수 (saf5400에 의존)
#elif defined(_SIGN_VERIFY_CRATON2_)
  kDot2SPDUProcessWorkNum_MaxProcessing = 12 ///< craton2가 동시에 처리 가능한 최대 작업 수 (craton2에 의존) (5.12.0)
                                             ///< ecc_service.h 의 ecc_request_send() 설명에는 64개까지 가능하다고 되어 있지만,
                                             ///< 테스트 결과, 13개 이상부터는 드라이버 레벨에서 에러가 출력되고 SPDU가 폐기된다.
                                             ///< (craton.ko) ecc_server_request:637: ecultra_driver_work_alloc failed, rc=11
#endif
};
typedef unsigned int Dot2SPDUProcessWorkNum; ///< @ref eDot2SPDUProcessWorkNum


/**
 * @brief SPDU 처리 작업 데이터
 */
struct Dot2SPDUProcessWorkData
{
  uint8_t *spdu; ///< 처리할 SPDU(어플리케이션이 전달한 파라미터로부터 동적할당되어 복사됨)
  Dot2SPDUSize spdu_size; ///< 처리할 SPDU의 길이
  struct Dot2SPDUProcessParams params; ///< (어플리케이션이 라이브러리로 전달한) SPDU 처리를 위한 파라미터
  struct V2XPacketParseData *parsed; ///< (어플리케이션이 라이브러리로 전달한) 패킷파싱데이터 (libdot2가 해제해서는 안됨)
  struct Dot2ECPublicKey signer_pub_key; ///< SPDU에 서명한 서명자인증서 공개키 (재구성된 공개키)
  struct Dot2SHA256 signer_h; ///< SPDU에 서명한 서명자인증서에 대한 해시값
  struct Dot2EECertCacheEntry *new_signer_entry; ///< 새로운 서명자인증서 정보 엔트리 (처음으로 수신한 서명자인증서의 경우 새롭게 할당됨)
  struct Dot2EECertCacheEntry *signer_entry; ///< 기존 서명자인증서 정보 엔트리 포인터 (이미 수신되어 테이블에 저장되어 있는 서명자인증서의 경우 주소가 저장됨)
  struct Dot2SHA256 tbs_h; ///< SPDU 내 ToBeSignedData 필드에 대한 해시값 (서명검증에 사용됨)
  struct Dot2Signature sign; ///< SPDU 내 포함된 서명
#if defined(_SIGN_VERIFY_OPENSSL_)
  EC_KEY *eck_signer_pub_key;  ///< SPDU에 서명한 서명자인증서 공개키 (재구성된 공개키)
#endif
#if defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
  struct Dot2ECPublicKey signer_recon_pub; ///< SPDU에 서명한 서명자인증서 공개키 재구성값 (비압축형식)
#endif
};


/**
 * @brief SPDU 처리 작업 정보 (작업 큐에 저장된다)
 */
struct Dot2SPDUProcessWork
{
  Dot2SPDUProcessWorkType type; ///< 작업 유형
  struct Dot2SPDUProcessWorkData data; ///< 작업 데이터
  int result; ///< 작업결과 (kDot2Result_Success or -Dot2ResultCode)
#if defined(_SIGN_VERIFY_SAF5400_)
  uint16_t usn; ///< 작업 고유번호. saf5400으로 전달되며 콜백함수에서 결과-요청 사이의 매칭을 찾는데 사용된다.
#if defined(_DSRC_CHIP_DEV_SAF5400_SDK_VER_0_15_)
  uint8_t req[sizeof(tMKxC2XSec) + MKXC2XSEC_CMD_VSOH256_LC]; ///< LLC로의 요청정보 (struct tMKxC2XSec + Payload)
#else
  tMKxC2XSec req; ///< LLC로의 요청정보
#endif
#elif defined(_SIGN_VERIFY_CRATON2_)
  uint32_t uid; ///< 작업 고유번호. craton2로 전달되며 결과 수신 쓰레드에서 결과-요청 사이의 매칭을 찾는데 사용된다.
#endif
  TAILQ_ENTRY(Dot2SPDUProcessWork) entries;
};
TAILQ_HEAD(Dot2SPDUProcessWorkHead, Dot2SPDUProcessWork);


/**
 * @brief SPDU 처리 작업 큐
 */
struct Dot2SPDUProcessWorkQueue
{
  Dot2SPDUProcessWorkNum work_cnt; ///< 작업 큐에 저장되어 있는 작업의 개수
  struct Dot2SPDUProcessWorkHead head;
};


/**
 * @brief SPDU 처리 기능에 대한 관리정보
 */
struct Dot2SPDUProcess
{
  struct {
    struct Dot2SPDUProcessWorkQueue req_q; ///< 작업정보(요청) 큐 (어플리케이션이 요청한 작업이 저장된다)
    pthread_mutex_t req_mtx; ///< 작업정보(요청) 큐 접근 뮤텍스
    pthread_cond_t req_cond; ///< 작업정보(요청) 발생 시그널
    pthread_t req_thread; ///< 작업정보(요청) 처리 쓰레드
    bool req_thread_running; ///< 작업정보(요청) 처리 쓰레드 동작 여부
    Dot2SPDUProcessWorkNum processing_cnt; ///< 현재 처리 중인 작업의 개수. 작업정보(대기) 큐의 작업정보 수와 동일하다.

#if defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
    struct Dot2SPDUProcessWorkQueue wait_q; ///< 작업정보(대기) 큐 (H/W 등에 의해 현재 진행 중인 작업이 저장된다)
    pthread_mutex_t wait_mtx; ///< 작업정보(대기) 큐 접근 뮤텍스
#if defined(_SIGN_VERIFY_CRATON2_)
    pthread_t wait_thread; ///< 작업정보(대기) 처리 쓰레드
    bool wait_thread_running; ///< 작업정보(대기) 처리 쓰레드 동작 여부
#endif
#endif

    struct Dot2SPDUProcessWorkQueue res_q; ///< 작업정보(결과) 큐 (완료된 작업의 결과가 저장된다)
    pthread_mutex_t res_mtx; ///< 작업정보(결과) 큐 접근 뮤텍스
    pthread_cond_t res_cond; ///< 작업정보(결과) 발생 시그널
    pthread_t res_thread; ///< 작업정보(결과) 처리 쓰레드
    bool res_thread_running; ///< 작업정보(결과) 처리 쓰레드 동작 여부
  } work;

  ProcessSPDUCallback cb; ///< SPDU 처리 결과를 전달할 어플리케이션 콜백함수 포인터.
                          ///< Dot2_RegisterProcessSPDUCallback() API에 의해 등록된다.
};


#ifdef __cplusplus
}
#endif


#endif //V2X_SW_DOT2_SPDU_H
