/** 
  * @file 
  * @brief 
  * @date 2021-06-03 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <unistd.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-profile/dot2-sec-profile-inline.h"
#include "spdu/dot2-spdu.h"


/**
 * @brief SPDU 처리 기능을 초기화한다.
 * @param[in] spdu_process SPDU 처리기능 관리정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_InitSPDUProcessFunction(struct Dot2SPDUProcess *spdu_process)
{
  Log(kDot2LogLevel_Event, "Initialize SPDU process function\n");

  /*
   * 작업정보(요청) 큐, 작업정보(대기) 큐, 작업정보(결과) 큐를 초기화한다.
   */
  dot2_InitSPDUProcessWorkQueue(&(spdu_process->work.req_q));
  pthread_mutex_init(&(spdu_process->work.req_mtx), NULL);
  pthread_cond_init(&(spdu_process->work.req_cond), NULL);
#if defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
  dot2_InitSPDUProcessWorkQueue(&(spdu_process->work.wait_q));
  pthread_mutex_init(&(spdu_process->work.wait_mtx), NULL);
#endif
  dot2_InitSPDUProcessWorkQueue(&(spdu_process->work.res_q));
  pthread_mutex_init(&(spdu_process->work.res_mtx), NULL);
  pthread_cond_init(&(spdu_process->work.res_cond), NULL);

  /*
   * 작업정보 처리 관련 쓰레드들을 생성한다.
   */
  int ret = -kDot2Result_FailToCreateThread;
  struct timespec req = { .tv_sec = 0, .tv_nsec = 10000000 }, rem;
  // 작업정보(요청) 처리 쓰레드 생성.
  if (pthread_create(&(spdu_process->work.req_thread), NULL, dot2_SPDUProcessWorkRequestHandleThread, NULL) == 0) {
    while (spdu_process->work.req_thread_running == false) {
      nanosleep(&req, &rem);
    }
    // 작업정보(결과) 처리 쓰레드 생성.
    if (pthread_create(&(spdu_process->work.res_thread), NULL, dot2_SPDUProcessWorkResultHandleThread, NULL) == 0) {
      while (spdu_process->work.res_thread_running == false) {
        nanosleep(&req, &rem);
      }
#if defined(_SIGN_VERIFY_CRATON2_)
      // 작업정보(대기) 처리 쓰레드 생성.
      if (pthread_create(&(spdu_process->work.wait_thread), NULL, dot2_SPDUProcessWorkWaitHandleThread, NULL) == 0) {
        struct timespec req = { .tv_sec = 1, .tv_nsec = 0 }, rem;
        while (spdu_process->work.wait_thread_running == false) {
          nanosleep(&req, &rem);
        }
        ret = kDot2Result_Success;
      }
#else
      ret = kDot2Result_Success;
#endif
    }
  }
  return ret;
}


/**
 * @brief SPDU 처리 기능을 종료한다.
 * @param[in] spdu_process SPDU 처리기능 관리정보
 */
void INTERNAL dot2_ReleaseSPDUProcessFunction(struct Dot2SPDUProcess *spdu_process)
{
  Log(kDot2LogLevel_Event, "Release SPDU process function\n");

  /*
   * 작업정보(요청) 큐를 비우고 작업정보(요청) 처리 쓰레드를 종료시킨다.
   */
  pthread_mutex_lock(&(spdu_process->work.req_mtx));
  dot2_FlushSPDUProcessWorkQueue(&(spdu_process->work.req_q));
  if (spdu_process->work.req_thread_running == true) {
    spdu_process->work.req_thread_running = false;
    pthread_cond_signal(&(spdu_process->work.req_cond));
  }
  pthread_mutex_unlock(&(spdu_process->work.req_mtx));
  pthread_join(spdu_process->work.req_thread, NULL);

#if defined(_SIGN_VERIFY_SAF5400_) || defined(_SIGN_VERIFY_CRATON2_)
  /*
   * 작업정보(대기) 큐를 비우고 작업정보(대기) 처리 쓰레드를 종료시킨다.
   */
  pthread_mutex_lock(&(spdu_process->work.wait_mtx));
  dot2_FlushSPDUProcessWorkQueue(&(spdu_process->work.wait_q));
#if defined(_SIGN_VERIFY_CRATON2_)
  if (spdu_process->work.wait_thread_running == true) {
    spdu_process->work.wait_thread_running = false;
  }
#endif
  pthread_mutex_unlock(&(spdu_process->work.wait_mtx));
#if defined(_SIGN_VERIFY_CRATON2_)
  pthread_join(spdu_process->work.wait_thread, NULL);
#endif
#endif

  /*
   * 작업정보(결과) 큐를 비우고 작업정보(결과) 처리 쓰레드를 종료시킨다.
   */
  pthread_mutex_lock(&(spdu_process->work.res_mtx));
  dot2_FlushSPDUProcessWorkQueue(&(spdu_process->work.res_q));
  if (spdu_process->work.res_thread_running == true) {
    spdu_process->work.res_thread_running = false;
    pthread_cond_signal(&(spdu_process->work.res_cond));
  }
  pthread_mutex_unlock(&(spdu_process->work.res_mtx));
  pthread_join(spdu_process->work.res_thread, NULL);
}


/**
 * @brief SPDU에 대한 Consistency 및 Relevance check를 수행한다.
 * @param[in] work SPDU 처리작업정보
 * @param[in] signer_entry 서명자인증서 정보 엔트리
 * @retval kDot2Result_SPDUVerificationInNotNecessary: 성공 - 더 이상의 후속처리가 불필요한 경우
 * @retval kDot2Result_Success: 성공 - 후속처리(공개키재구성 or 서명검증)가 필요한 경우
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL
dot2_ProcessSPDUConsistencyAndRelevanceCheck(struct Dot2SPDUProcessWork *work, struct Dot2EECertCacheEntry *signer_entry)
{
  int ret;
  Log(kDot2LogLevel_Event, "Process SPDU consistency & relevance check\n");

  /*
   * PSID에 해당되는 Security profile을 찾는다.
   */
  struct Dot2SecProfileEntry *sec_profile_entry = dot2_FindSecProfile(work->data.params.rx_psid);
  if (sec_profile_entry == NULL) {
    Err("Fail to process SPDU consistency & relevance check - no security profile for PSID(%u)\n",
        work->data.params.rx_psid);
    return -kDot2Result_NoSuchSecProfileInTable;
  }

  /*
   * 해당 PSID에 대해 검증이 필요없을 경우, 그냥 성공을 리턴한다.
   */
  if (sec_profile_entry->profile.rx.verify_data == false) {
    Log(kDot2LogLevel_Event, "Consistency and relevance check is not needed\n");
    return kDot2Result_SPDUVerificationInNotNecessary;
  }

  /*
   * 수신 PSID와 SPDU 내 PSID가 동일한지 확인한다.
   */
  if (work->data.params.rx_psid != work->data.parsed->spdu.signed_data.psid) {
    Err("Fail to process SPDU consistency & relevance check - different PSID between lower layer PDU(%u) and SPDU(%u)\n",
        work->data.params.rx_psid, work->data.parsed->spdu.signed_data.psid);
    return -kDot2Result_DifferentPSID;
  }

  /*
   * Consistency check 및 Relevance check를 수행한다.
   */
  ret = dot2_CheckSPDUConsistency(work->data.parsed, &(sec_profile_entry->profile), signer_entry);
  if (ret == kDot2Result_Success) {
    ret = dot2_CheckSPDURelevance(&(work->data), sec_profile_entry, signer_entry);
  }

  return ret;
}
