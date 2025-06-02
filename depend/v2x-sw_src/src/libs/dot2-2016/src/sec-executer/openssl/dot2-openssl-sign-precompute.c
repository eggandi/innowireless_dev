/**
 * @file
 * @brief OpenSSL 기반 서명 생성 파라미터 사전 계산 관련 구현
 * @date 2020-04-11
 * @author gyun
 */


// 시스템 헤더파일
#include <unistd.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-openssl-inline.h"


/**
 * @brief 서명 파라미터를 생성한다.
 * @return 생성된 서명 파라미터 포인터
 * @retval NULL: 생성 실패
 */
static inline struct Dot2OsslSigningParameters * dot2_ossl_GenerateSigningParameters(void)
{
  struct Dot2OsslSigningParameters *params = calloc(1, sizeof(struct Dot2OsslSigningParameters));
  if (params) {
    if (dot2_ossl_ComputeSigningParameters(params) == kDot2Result_Success) {
      return params;
    }
    free(params);
    params = NULL;
  }
  return NULL;
}


/**
 * @brief 서명 파라미터를 해제한다.
 * @param[in] params 해제할 서명 파라미터
 */
static inline void dot2_ossl_FreeSigningParameters(struct Dot2OsslSigningParameters *params)
{
  BN_free(params->bn_kinv);
  BN_free(params->bn_r);
  free(params);
}


/**
 * @brief 서명파라미터를 교체한다. 가장 오래된 파라미터(리스트의 첫번째 엔트리)를 빼내고, 새로운 파라미터를 리스트의 끝에 추가한다.
 * @param[in] list 서명파라미터 리스트
 * @param[in] new 새로 추가할 서명파라미터
 * @return 리스트에서 빼낸 가장 오래된 파라미터
 * @retval NULL: 파라미터가 없을 경우(라이브러리 초기화 루틴에서 기본적으로 10개의 엔트리를 생성하고 시작하므로 이럴 일은 없다)
 */
static inline struct Dot2OsslSigningParameters *
dot2_ossl_ReplaceSigningParameters(struct Dot2OsslSigningParametersList *list, struct Dot2OsslSigningParameters *new)
{
  struct Dot2OsslSigningParameters *oldest = TAILQ_FIRST(&(list->head));
  if (oldest) {
    if (list->current == oldest) {
      list->current = TAILQ_NEXT(oldest, entries);
    }
    TAILQ_REMOVE(&(list->head), oldest, entries);
    TAILQ_INSERT_TAIL(&(list->head), new, entries);
  }
  return oldest;
}


/**
 * @brief 서명 파라미터 사용 카운트를 증가시킨다.
 * @param[in] cnt 서명 파라미터 사용 카운트
 * @return 증가된 사용 카운트
 */
static inline unsigned int dot2_ossl_IncreaseSigningParametersConsumeCnt(unsigned int cnt)
{
  return ((cnt == UINT_MAX) ? UINT_MAX : (cnt + 1));
}


/**
 * @brief 서명 파라미터 사용 카운트를 감소시킨다.
 * @param[in] cnt 서명 파라미터 사용 카운트
 * @return 감소된 사용 카운트
 */
static inline unsigned int dot2_ossl_DecreaseSigningParametersConsumeCnt(unsigned int cnt)
{
  return ((cnt == 0) ? 0 : (cnt - 1));
}


/**
 * @brief 서명 파라미터 계산 쓰레드
 * @param[in] arg 타원곡선 정보
 * @return NULL
 *
 * 서명 생성 시 필요한 파라미터들을 평소에 일정 주기로 계산하여 서명파라미터 리스트에 넣어 둔다.
 * (서명 생성 시점의 지연을 줄이기 위해)
 * 서명 생성 루틴에서 서명파라미터 리스트 내에 저장되어 있던 서명파라미터(들)이 사용되었으면,
 * 그 중 가장 오래된 서명파라미터를 리스트에서 제거하고 새로운 서명파라미터를 추가한다.
 *
 * 시스템 로드를 줄이기 위해 일정 주기(기본 100msec, list->compute_interval)마다 해당 작업을 수행한다.
 * 만약 서명생성 주기가 이보다 더 짧아서, 서명파라미터 리스트에 새로운 서명파라미터가 업데이트 되기 전에 리스트 내 모든 서명파라미터가
 * 소진되어 버리면, 이미 사용된 서명파라미터를 재사용하게 된다.
 *
 * 재사용을 방지하기 위해 본 루틴을 보다 빠른 주기로 수행할 경우 시스템 로드가 증가할 수 있어 재사용은 감수한다.
 * 시스템 성능에 따라 적절한 주기를 찾아 적용할 수 있다.
 */
static void * dot2_ossl_SigningParametersComputeThread(void *arg)
{
  (void)arg;
  struct Dot2OsslSigningParametersList *list = &(g_dot2_mib.sec_executer.ossl.sign_params_list);
  struct Dot2OsslSigningParameters *params = NULL;

  Log(kDot2LogLevel_Event, "Success to create sign parameter compute thread\n");
  list->thread_running = true;

  struct Dot2OsslSigningParameters *removed;
  struct timespec req, rem;
  req.tv_sec = list->compute_interval / 1000;
  req.tv_nsec = (list->compute_interval % 1000) * 1000000;
  while (1)
  {
    // 정해진 시간만큼 지연하여 시스템 로드를 줄인다.
    nanosleep(&req, &rem);

    // 쓰레드 종료 요청 상태면 쓰레드를 종료한다.
    if (list->thread_running == false) {
      if (params) {
        free(params);
      }
      break;
    }

    // 새로운 서명파라미터를 생성해 둔다.
    // 직전 회차에 생성해 둔 서명파라미터가 리스트에 수납되지 않았다면(params!=NULL) 생성하지 않고 재활용한다.
    if (params == NULL) {
      params = dot2_ossl_GenerateSigningParameters();
      if (params == NULL) {
        Err("Fail to generate\n");
        sleep(1);
        continue;
      }
    }

    // 리스트 내에 소진된 서명파라미터가 존재하면 새로운 파라미터로 교체한다.
    pthread_mutex_lock(&(g_dot2_mib.mtx));
    removed = NULL;
    if (list->consume_cnt > 0) {
      removed = dot2_ossl_ReplaceSigningParameters(list, params);
      if (removed) {
        list->consume_cnt = dot2_ossl_DecreaseSigningParametersConsumeCnt(list->consume_cnt);
      }
    }
    pthread_mutex_unlock(&(g_dot2_mib.mtx));

    // 소진된 서명파라미터를 해제한다.
    // 새로 생성한 서명파라미터 포인터(params)를 null로 설정하여 다음 회차에 새로운 서명파라미터를 생성하도록 한다.
    if (removed) {
      dot2_ossl_FreeSigningParameters(removed);
      params = NULL;
    }
  }

  Log(kDot2LogLevel_Event, "Sign paramter compute thread exits\n");
  return NULL;
}


/**
 * @brief 서명 파라미터 계산 기능을 초기화한다.
 * @param[in] interval 서명파라미터 계산 주기
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_InitSigningParametersComputeFunction(Dot2SigningParamsPrecomputeInterval interval)
{
  Log(kDot2LogLevel_Init, "Initialize signing parameters compute function\n");
  struct Dot2OsslSigningParametersList *list = &(g_dot2_mib.sec_executer.ossl.sign_params_list);

  memset(list, 0, sizeof(struct Dot2OsslSigningParametersList));
  TAILQ_INIT(&(list->head));
  list->compute_interval = interval;

  /*
   * 초기 서명 파라미터들을 생성하여 저장한다.
   */
  struct Dot2OsslSigningParameters *params;
  for (unsigned int i = 0; i < DOT2_PRECOMPUTED_SIGN_PARAMS_NUM; i++) {
    params = dot2_ossl_GenerateSigningParameters();
    if (params == NULL) {
      Err("Fail to initialize sign parameters compute function - dot2_ossl_GenerateSignParameters() failed\n");
      return -kDot2Result_FailToInitSignParameterComputeFunction;
    }
    TAILQ_INSERT_TAIL(&(list->head), params, entries);
  }
  list->current = TAILQ_LAST(&(list->head), Dot2OsslSigningParametersHead);

  /*
   * 서명 파라미터 계산 쓰레드를 생성한다.
   */
  struct timespec req = { .tv_sec = 0, .tv_nsec = 10000000 }, rem;
  if (pthread_create(&(list->thread), NULL, dot2_ossl_SigningParametersComputeThread, NULL) == 0) {
    while (list->thread_running == false) {
      nanosleep(&req, &rem);
    }
  } else {
    Err("Fail to initialize sign parameters compute function - pthread_create() failed: %m\n");
    return -kDot2Result_FailToInitSignParameterComputeFunction;
  }

  Log(kDot2LogLevel_Init, "Success to initialize sign parameters compute function\n");
  return kDot2Result_Success;
}


/**
 * @brief 서명 파라미터 리스트를 비운다.
 * @param[in] list 서명 파라미터 리스트
 */
void INTERNAL dot2_ossl_FlushSigningParametersList(struct Dot2OsslSigningParametersList *list)
{
  struct Dot2OsslSigningParameters *params, *tmp;
  TAILQ_FOREACH_SAFE(params, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), params, entries);
    dot2_ossl_FreeSigningParameters(params);
  }
  list->current = NULL;
}
