/** 
  * @file 
  * @brief 
  * @date 2021-06-03 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <assert.h>
#include <unistd.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-spdu-inline.h"


/**
 * @brief 새로운 작업정보를 할당한다.
 * @param[in] spdu 작업정보에 저장될 SPDU
 * @param[in] spdu_size 작업정보에 저장될 SPDU의 길이
 * @param[in] params SPDU 처리를 위한 파라미터
 * @param[in] parsed 작업정보에 저장될 패킷파싱데이터
 * @return 할당된 작업정보 포인터
 * @retval NULL: 할당 실패
 */
static inline struct Dot2SPDUProcessWork *dot2_AllocateSPDUProcessWork(
  uint8_t *spdu,
  Dot2SPDUSize spdu_size,
  struct Dot2SPDUProcessParams *params,
  struct V2XPacketParseData *parsed)
{
  struct Dot2SPDUProcessWork *work = (struct Dot2SPDUProcessWork *)calloc(1, sizeof(struct Dot2SPDUProcessWork));
  if (work) {
    work->type = kDot2SPDUProcessWorkType_Parse; // 수신된 모든 SPDU의 첫 작업은 파싱이다.
    work->data.parsed = parsed;
    work->data.spdu = (uint8_t *)malloc(spdu_size);
    if (work->data.spdu == NULL) {
      free(work);
      return NULL;
    }
    memcpy(work->data.spdu, spdu, spdu_size);
    work->data.spdu_size = spdu_size;
    work->data.params = *params;
    return work;
  }
  return NULL;
}


/**
 * @brief 작업정보를 작업정보(요청) 큐에 추가한다.
 * @param[in] spdu_process SPDU 처리기능 관리정보
 * @param[in] work 추가할 작업정보
 * @param[in] type 작업 유형
 * @param[in] result 작업 결과
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_PushSPDUProcessWorkRequest(
  struct Dot2SPDUProcess *spdu_process,
  struct Dot2SPDUProcessWork *work,
  Dot2SPDUProcessWorkType type,
  int result)
{
  work->type = type;
  work->result = result;
  pthread_mutex_lock(&(spdu_process->work.req_mtx));
  int ret = dot2_PushSPDUProcessWork(&(spdu_process->work.req_q), work);
  if (ret == kDot2Result_Success) {
#if defined(_SIGN_VERIFY_OPENSSL_)
    if (spdu_process->work.req_q.work_cnt == 1) { // 작업정보(요청)큐가 비어 있었으면 작업정보(요청) 처리 쓰레드를 깨운다.
      pthread_cond_signal(&(spdu_process->work.req_cond));
    }
#elif defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
    if ((spdu_process->work.req_q.work_cnt == 1) || // 작업정보(요청)큐가 비어 있었으면 작업정보(요청) 처리 쓰레드를 깨운다.
        (spdu_process->work.processing_cnt < kDot2SPDUProcessWorkNum_MaxProcessing)) { // 처리여력이 남아있을 경우에도 깨운다.
      pthread_cond_signal(&(spdu_process->work.req_cond));
    }
#else
#error "Signature verification method is not defined"
#endif
  } else {
    ret = -kDot2Result_SPDUProcessWorkRequestQueueFull;
  }
  pthread_mutex_unlock(&(spdu_process->work.req_mtx));
  return ret;
}


/**
 * @brief 작업정보를 작업정보(결과) 큐에 추가한다.
 * @param[in] spdu_process SPDU 처리기능 관리정보
 * @param[in] work 추가할 작업정보
 * @param[in] result 작업 결과
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_PushSPDUProcessWorkResult(
  struct Dot2SPDUProcess *spdu_process,
  struct Dot2SPDUProcessWork *work,
  int result)
{
  work->result = result;
  pthread_mutex_lock(&(spdu_process->work.res_mtx));
  int ret = dot2_PushSPDUProcessWork(&(spdu_process->work.res_q), work);
  if (ret == kDot2Result_Success) {
    if (spdu_process->work.res_q.work_cnt == 1) { // 작업정보(결과)큐가 비어 있었으면, 작업정보(결과) 처리 쓰레드를 깨운다.
      pthread_cond_signal(&(spdu_process->work.res_cond));
    }
  } else {
    ret = -kDot2Result_SPDUProcessWorkResultQueueFull;
  }
  pthread_mutex_unlock(&(spdu_process->work.res_mtx));
  return ret;
}


/**
 * @brief 작업정보(요청) 큐에 들어 있던 작업정보를 처리한다.
 * @param[in] work 처리할 작업정보
 */
static void dot2_ProcessSPDUProcessWorkRequest(struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Process SPDU process work(request)\n");
  struct Dot2SPDUProcess *spdu_process = &(g_dot2_mib.spdu_process);
  int ret;

  /*
   * 작업 유형에 따라 처리한다.
   */
  if (work->type == kDot2SPDUProcessWorkType_Parse) {
    ret = dot2_ParseAndProcessSPDU(work);
  } else if (work->type == kDot2SPDUProcessWorkType_SignVerification) {
    ret = kDot2Result_SPDUProcess_RequestSignatureVerification; // 아래에서 수행되도록 한다.
#if defined(_SIGN_VERIFY_SAF5400_)
  } else if (work->type == kDot2SPDUProcessWorkType_SignerPublicKeyReconstruction) {
    ret = kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstruction; // 아래에서 수행되도록 한다.
#endif
  } else {
    assert(0);
  }

  /*
   * 1) Openssl 기반 서명검증 지원 시:
   *  - 서명검증이 필요하면 서명검증을 수행하고 그 결과를 작업정보(결과)큐에 저장하여 어플리케이션에게 전달한다.
   * 2) saf5400,craton2 기반 서명검증 지원 시:
  *   - 서명검증이 필요하면 H/W에 서명검증 수행을 요청한다. 결과는 콜백이나 다른 쓰레드에서 수신된다
   *  - 서명검증 요청이 실패하면 작업을 종료한다. (작업정보(결과)큐에 저장하여 어플리케이션에게 실패결과가 전달되도록 한다)
   */
  if (ret == kDot2Result_SPDUProcess_RequestSignatureVerification) {
    ret = dot2_VerifySPDUSignature(work);
#if defined(_SIGN_VERIFY_OPENSSL_)
    if (ret == kDot2Result_Success) {
      ret = dot2_ProcessSPDUProcessWork_SignVerificationResult(work);
    }
    goto finish;
#elif defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
    if (ret < 0) {
      goto finish;
    }
#else
#error "Signature verification method is not defined"
#endif
  }

  /*
   * 1) Openssl 기반 서명검증 지원 시:
   *  - 공개키 재구성이 필요하면 공개키 재구성과 서명검증을 수행하고 그 결과를 작업정보(결과)큐에 저장하여 어플리케이션에게 전달한다.
   * 2) saf5400,craton2 기반 서명검증 지원 시:
   *  - 공개키 재구성이 필요하면 H/W에 공개키 재구성 수행을 요청한다. 결과는 콜백이나 다른 쓰레드에서 수신된다
   *  - 공개키 재구성 요청이 실패하면 작업을 종료한다. (작업정보(결과)큐에 저장하여 어플리케이션에게 실패결과가 전달되도록 한다)
   */
  else if (ret == kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstruction) {
    ret = dot2_ReconstructSPDUSignerPublicKey(work);
    if (ret < 0) {
      goto finish;
    }
#if defined(_SIGN_VERIFY_OPENSSL_)
    ret = dot2_VerifySPDUSignature(work);
    if (ret == kDot2Result_Success) {
      ret = dot2_ProcessSPDUProcessWork_SignVerificationResult(work);
    }
    goto finish;
#endif
  }

#if defined (_SIGN_VERIFY_SAF5400_)
  /*
   * 공개키재구성값 복구가 필요하면 Y좌표 복구 수행을 요청한다. 결과는 콜백이나 다른 쓰레드에서 수신된다
   *  - 공개키재구성값 복구 요청이 실패하면 작업을 종료한다. (작업정보(결과)큐에 저장하여 어플리케이션에게 실패결과가 전달되도록 한다)
   */
  else if (ret == kDot2Result_SPDUProcess_RequestSignerPublicKeyReconstructionValueRecovery) {
    ret = dot2_saf5400_RequestSignerPublicKeyReconstructionValueRecovery(work);
    if (ret < 0) {
      goto finish;
    }
  }
#endif

  /*
   * 파싱 작업이 성공적으로 끝났으면, 작업을 종료한다.
   * 이 조건문에 해당되는 경우는 다음과 같다.
   *  - Unsecured SPDU인 경우
   *  - Signed SPDU이지만, Security profile의 verify_data=false 여서 SPDU 검증이 필요없는 경우
   */
  else if (ret == kDot2Result_Success) {
    goto finish;
  }

  /*
   * 파싱 작업이 실패(ret < 0)하거나 오류 상황(리턴값이 양수)에서는, 작업을 종료한다.
   */
  else {
    Err("Fail to process SPDU process work(request) - ret: %d\n", ret);
    goto finish;
  }

  return;

  /*
   * 작업 종료 -> 수행 결과를 결과를 작업결과큐에 저장하여 콜백함수를 통해 어플리케이션으로 결과가 전달되도록 한다.
   */
finish:
  Log(kDot2LogLevel_Event, "Finish process\n");
  work->type = kDot2SPDUProcessWorkType_ApplicationCallback;
  dot2_PushSPDUProcessWorkResult(spdu_process, work, ret);
}


/**
 * @brief SPDU 처리 작업정보 큐를 초기화한다.
 * @param[in] q 작업정보 큐
 */
void INTERNAL dot2_InitSPDUProcessWorkQueue(struct Dot2SPDUProcessWorkQueue *q)
{
  memset(q, 0, sizeof(struct Dot2SPDUProcessWorkQueue));
  TAILQ_INIT(&(q->head));
}


/**
 * @brief 작업정보 큐를 비운다.
 * @param[in] q 작업정보 큐
 */
void INTERNAL dot2_FlushSPDUProcessWorkQueue(struct Dot2SPDUProcessWorkQueue *q)
{
  struct Dot2SPDUProcessWork *work, *tmp;
  TAILQ_FOREACH_SAFE(work, &(q->head), entries, tmp) {
    TAILQ_REMOVE(&(q->head), work, entries);
    dot2_FreeSPDUProcessWork(work);
  }
  q->work_cnt = 0;
}


/**
 * @brief 새로운 SPDU 처리 작업정보를 작업정보(요청)큐에 추가한다. (작업정보(요청) 처리 쓰레드에서 처리된다)
 * @param[in] spdu 처리할 SPDU (작업정보 내에 저장된다)
 * @param[in] spdu_size 처리할 SPDU의 길이 (작업정보 내에 저장된다)
 * @param[in] params SPDU 처리를 위한 파라미터
 * @param[in] parsed 패킷파싱데이터 (작업정보 내에 저장된다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_AddNewSPDUProcessWorkRequest(
  uint8_t *spdu,
  Dot2SPDUSize spdu_size,
  struct Dot2SPDUProcessParams *params,
  struct V2XPacketParseData *parsed)
{
  Log(kDot2LogLevel_Event, "Add new SPDU process work(request)\n");

  /*
   * 새로운 SPDU 처리 작업정보를 작업정보(요청) 큐에 추가한다 -> 해당 작업은 작업정보(요청) 처리 쓰레드에서 처리된다.
   */
  int ret = -kDot2Result_NoMemory;
  struct Dot2SPDUProcessWork *work = dot2_AllocateSPDUProcessWork(spdu, spdu_size, params, parsed);
  if (work) {
    ret = dot2_PushSPDUProcessWorkRequest(&(g_dot2_mib.spdu_process), work, work->type, kDot2Result_Success);
    if (ret == kDot2Result_Success) {
      Log(kDot2LogLevel_Event, "Success to add new SPDU process work(request)\n");
    } else {
      Err("Fail to add new SPDU process work(request) - dot2_PushSPDUProcessWorkRequest() failed: %d\n", ret);
    }
  }
  return ret;
}

#if defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
/**
 * @brief 작업정보(대기) 큐에 들어 있던 작업정보를 처리한다.
 * @param[in] result 작업처리 결과
 * @param[in] work 작업정보
 */
void INTERNAL dot2_ProcessSPDUProcessWorkWait(int result, struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Process SPDU process work(wait) - result: %d\n", result);
  struct Dot2SPDUProcess *spdu_process = &(g_dot2_mib.spdu_process);
  int ret;

  /*
   * 처리 결과가 실패이면, 실패결과를 담은 작업정보를 결과큐에 저장한다 -> 작업정보(결과) 처리 쓰레드에서 어플리케이션으로 전달된다.
   */
  if (result != kDot2Result_Success) {
    dot2_PushSPDUProcessWorkResult(spdu_process, work, result);
    return;
  }

  /*
   * 서명검증 결과를 처리하고, 결과를 담은 작업정보를 작업정보(결과) 큐에 저장한다 -> 작업정보(결과) 처리 쓰레드에서 어플리케이션으로 전달된다.
   */
  if (work->type == kDot2SPDUProcessWorkType_SignVerification) {
    dot2_ProcessSPDUProcessWork_SignVerificationResult(work);
    dot2_PushSPDUProcessWorkResult(spdu_process, work, work->result);
    return;
  }

  /*
   * 공개키 재구성 결과를 처리하고, 서명검증에 대한 작업정보를 작업정보(요청)큐에 저장한다 -> 작업정보(요청) 처리 쓰레드에서 서명검증이 수행된다.
   *  - 공개키 재구성 결과는 전단계(saf5400: 콜백함수, craton2: 결과수신쓰레드)에서 이미 작업정보에 저장되었으므로,
   *    여기서는 딱히 수행할 게 없고, 다음 작업인 서명검증 작업을 요청한다.
   */
  else if (work->type == kDot2SPDUProcessWorkType_SignerPublicKeyReconstruction) {
    ret = dot2_PushSPDUProcessWorkRequest(spdu_process, work, kDot2SPDUProcessWorkType_SignVerification, work->result);
  }

#if defined(_SIGN_VERIFY_SAF5400_)
  /*
   * 공개키재구성값 복구 결과를 처리하고, 공개키재구성에 대한 작업정보를 작업정보(요청)큐에 저장한다 -> 작업정보(요청) 처리 쓰레드에서 공개키재구성이 수행된다.
   *  - 공개키재구성값 복구 결과는 전단계(saf5400: 콜백함수)에서 이미 작업정보에 저장되었으므로,
   *    여기서는 딱히 수행할 게 없고, 다음 작업인 공개키재구성 작업을 요청한다.
   */
  else if (work->type == kDot2SPDUProcessWorkType_SignerPublicKeyReconstructionValueRecovery) {
    ret = dot2_PushSPDUProcessWorkRequest(spdu_process, work, kDot2SPDUProcessWorkType_SignerPublicKeyReconstruction, work->result);
  }
#endif

  /*
   * 유효하지 않은 작업 유형
   */
  else {
    assert(0);
  }

  /*
   * 에러 발생 시 에러 결과를 작업정보(결과) 큐에 저장한다 -> 작업정보(결과) 처리 쓰레드에서 어플리케이션으로 전달된다.
   */
  if (ret < 0) {
    dot2_PushSPDUProcessWorkResult(spdu_process, work, ret);
  }
}
#endif


/**
 * @brief 서명검증 결과를 처리한다 -> 필요 시, 새로운 서명자인증서 정보를 테이블에 저장한다.
 * @param[out] work 서명검증 결과가 저장될 작업정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 1. work->data.new_signer_entry에 정보가 존재하면;
 *   - 해당 서명자인증서가 처음으로 수신되었다는 의미이다 (즉, 해당 서명자인증서 정보가 EE 캐시정보 테이블에 존재하지 않음)
 *   - 따라서, 서명검증이 성공하면 해당 정보를 테이블에 추가한다.
 * 2. work->data.new_signer_entry에 정보가 존재하지 않으면;
 *   - 해당 서명자인증서에 대한 정보가 이미 EE 캐시정보 테이블에 저장되어 있다는 의미이다. (과거에 수신되어 저장되었음)
 *   - 따라서, 서명검증이 성공했는지 여부만 확인하고, 정보는 테이블에 추가하지 않는다.
 */
int INTERNAL dot2_ProcessSPDUProcessWork_SignVerificationResult(struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Process SPDU signature verification result - %d\n", work->result);

  int ret = work->result;

  /*
   * new_signer_entry가 존재하고 서명검증이 성공하였으면, 해당 정보를 인증서정보테이블에 저장한다.
   *  -> 서명자인증서가 처음으로 수신된 경우에 해당된다.
   *  -> CRL 테이블을 탐색하여 서명자인증서가 폐기되었는지 여부도 함께 저장한다.
   * new_signer_entry가 존재하지 않으면, 서명검증 결과만 작업정보에 업데이트한다.
   */
  struct Dot2EECertCacheEntry *new_signer_entry = work->data.new_signer_entry;
  if (new_signer_entry) {
    if (ret == kDot2Result_Success) { // 서명검증 성공
      pthread_mutex_lock(&(g_dot2_mib.mtx));
      dot2_UpdateEECertCacheEntryRevocation(new_signer_entry);
      ret = dot2_PushEECertCacheEntry(new_signer_entry);
      pthread_mutex_unlock(&(g_dot2_mib.mtx));
      if (ret == kDot2Result_Success) {
        work->data.new_signer_entry = NULL; // 인증서정보테이블에 저장되었으므로 work가 해제될 때 같이 해제되지 않도록 NULL로 설정한다.
        if (new_signer_entry->revoked) { // 폐기된 인증서이면 작업결과를 에러로 저장한다 -> 캐시에 저장해 놓고 다음번 수신때 폐기여부를 체크한다.
          ret = -kDot2Result_SPDUProcess_SignerRevoked;
        }
      }
    }
  }

  work->result = ret;
  return ret;
}


/**
 * @brief SPDU 처리 작업정보(요청)을 처리하는 쓰레드 (작업정보(요청) 큐에 저장된 작업정보를 꺼내서 처리한다)
 * @param[in] arg 사용되지 않음
 * @return NULL
 */
void INTERNAL * dot2_SPDUProcessWorkRequestHandleThread(void *arg)
{
  (void)arg;
  struct Dot2SPDUProcess *spdu_process = &(g_dot2_mib.spdu_process);
  struct Dot2SPDUProcessWorkQueue *req_q = &(spdu_process->work.req_q);

  Log(kDot2LogLevel_Event, "Success to start SPDU process work(request) handle thread\n");
  spdu_process->work.req_thread_running = true;

  struct Dot2SPDUProcessWork *work;
  while (1)
  {
#if defined(_SIGN_VERIFY_OPENSSL_)
    // 작업정보(요청)큐 내에 처리할 작업정보가 존재하면 작업정보를 큐에서 꺼내 처리한다.
    // 작업정보(요청)큐 내에 더이상 처리할 작업정보가 없으면 잠든다.
    pthread_mutex_lock(&(spdu_process->work.req_mtx));
    while ((spdu_process->work.req_thread_running == true) &&
           (req_q->work_cnt == 0)) {
      pthread_cond_wait(&(spdu_process->work.req_cond), &(spdu_process->work.req_mtx));
    }
#elif defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
    // 작업정보(요청)큐에 작업정보가 존재하고 추가적인 작업 처리가 가능하면 작업정보를 큐에서 꺼내 처리한다.
    // 작업정보(요청)큐 내에 더이상 처리할 작업정보가 없거나 최대 개수의 작업이 이미 처리 중이면 잠든다.
    pthread_mutex_lock(&(spdu_process->work.req_mtx));
    while ((spdu_process->work.req_thread_running == true) &&
           ((req_q->work_cnt == 0) ||
            (spdu_process->work.processing_cnt >= kDot2SPDUProcessWorkNum_MaxProcessing))) {
      pthread_cond_wait(&(spdu_process->work.req_cond), &(spdu_process->work.req_mtx));
    }
#else
#error "Signature verification method is not defined"
#endif

    // 쓰레드 종료 (어플리케이션 종료 시)
    if (spdu_process->work.req_thread_running == false) {
      pthread_mutex_unlock(&(spdu_process->work.req_mtx));
      break;
    }

    // 작업정보(요청) 큐에서 작업정보를 꺼낸다.
    work = TAILQ_FIRST(&(req_q->head));
    if (work) {
      TAILQ_REMOVE(&(req_q->head), work, entries);
      req_q->work_cnt--;
    }
    pthread_mutex_unlock(&(spdu_process->work.req_mtx));

    // 작업정보(요청)을 처리한다.
    if (work) {
      dot2_ProcessSPDUProcessWorkRequest(work);
    }
  }
  return NULL;
}


#if defined(_SIGN_VERIFY_CRATON2_)
/**
 * @brief SPDU 처리 작업정보(대기)를 처리하는 쓰레드 (작업정보(대기) 큐에 저장된 작업정보를 꺼내서 처리한다)
 * @param[in] arg 사용되지 않음
 * @return NULL
 */
void * dot2_SPDUProcessWorkWaitHandleThread(void *arg)
{
  (void)arg;
  struct Dot2SPDUProcess *spdu_process = &(g_dot2_mib.spdu_process);
  Log(kDot2LogLevel_Event, "Success to start SPDU process work(wait) handle thread\n");
  spdu_process->work.wait_thread_running = true;

  atlk_rc_t rc;
  ecc_response_t response;
  struct Dot2Craton2Executer *craton2 = &(g_dot2_mib.craton2);
  while (1)
  {
    // craton2의 보안 연산 결과를 수신한다(수신될 때까지 또는 타임아웃될 때까지 블록된다).
    atlk_wait_t wait;
    wait.wait_type = ATLK_WAIT_TYPE_INTERVAL;
    wait.wait_usec = 1000000;
    rc = ecc_response_receive(craton2->ecc_socket, &response, &wait);

    // 쓰레드 종료
    if (spdu_process->work.wait_thread_running == false) {
      break;
    }

    // 결과 수신 에러
    if (atlk_error(rc)) {
      if (rc != ATLK_E_TIMEOUT) {
        Err("Fail to ecc_response_receive(): %s\n", atlk_rc_to_str(rc));
      }
      continue;
    }

    // 수신된 결과에 따라 작업정보(대기)를 처리한다.
    dot2_craton2_ProcessSPDUProcessWorkWait(&response);
  }
  return NULL;
}
#endif


/**
 * @brief SPDU 처리 작업정보(결과)를 처리하는 쓰레드 (작업정보(결과) 큐에 저장된 작업정보를 꺼내서 처리한다 -> 어플리케이션에 전달한다)
 * @param[in] arg 사용되지 않음
 * @return NULL
 */
void * dot2_SPDUProcessWorkResultHandleThread(void *arg)
{
  (void)arg;
  struct Dot2SPDUProcess *spdu_process = &(g_dot2_mib.spdu_process);
  struct Dot2SPDUProcessWorkQueue *res_q = &(spdu_process->work.res_q);
  Log(kDot2LogLevel_Event, "Success to start SPDU process work(result) thread\n");
  spdu_process->work.res_thread_running = true;

  struct Dot2SPDUProcessWork *work;
  while (1)
  {
    // 작업정보(결과)큐에 작업정보가 존재하면 해당 작업정보를 처리한다.
    // 작업정보(결과)큐 내에 더이상 처리할 작업정보가 없으면 잠든다.
    pthread_mutex_lock(&(spdu_process->work.res_mtx));
    while ((spdu_process->work.res_thread_running == true) &&
           (res_q->work_cnt == 0)) {
      pthread_cond_wait(&(spdu_process->work.res_cond), &(spdu_process->work.res_mtx));
    }

    // 쓰레드 종료 (어플리케이션 종료 시)
    if (spdu_process->work.res_thread_running == false) {
      pthread_mutex_unlock(&(spdu_process->work.res_mtx));
      break;
    }

    // 작업정보(결과)큐에서 작업정보를 꺼낸다.
    work = TAILQ_FIRST(&(res_q->head));
    if (work) {
      TAILQ_REMOVE(&(res_q->head), work, entries);
      res_q->work_cnt--;
    }
    pthread_mutex_unlock(&(spdu_process->work.res_mtx));

    // 작업정보(결과)를 처리한다 -> SPDU 처리 결과를 콜백함수를 통해 어플리케이션으로 전달한다.
    if (work) {
      dot2_ProcessSPDUProcessWorkResult(work);
    }
  }
  return NULL;
}
