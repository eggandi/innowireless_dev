/** 
 * @file
 * @brief Openssl 기반 보안연산실행자 기능 구현
 * @date 2020-03-05
 * @author gyun
 */


// 라이브러리 의존 헤더 파일
#include "openssl/obj_mac.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"



/**
 * @brief Openssl 보안연산실행자에서 사용되는 타원곡선그룹 정보를 초기화한다.
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 실패 시 EC_GROUP,BN_CTX 정보 free()는 생략한다.
 *  - 기본적으로 실패하지 않는다.
 *  - 실패할 경우에도 라이브러리 초기화가 실패하여 어플리케이션이 종료되므로 자동으로 해제된다.
 */
static int dot2_ossl_InitSecExecuterECGROUP()
{
  Log(kDot2LogLevel_Event, "Initialize openssl security executer EC_GROUP\n");
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *ecg = NULL;
  int ret = -kDot2Result_OSSL_SecExecuterECGROUPInit;
  if (((bn_ctx = BN_CTX_new()) != NULL) &&
      ((ecg = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) != NULL) &&
      (EC_GROUP_precompute_mult(ecg, bn_ctx) == DOT2_OSSL_SUCCESS)) {
    g_dot2_mib.sec_executer.ossl.ecg = ecg;
    BN_CTX_free(bn_ctx);
    ret = kDot2Result_Success;
  }
  return ret;
}


/**
 * @brief Openssl 보안연산실행자에서 사용되는 타원곡선그룹 정보를 해제한다.
 */
static void dot2_ossl_ReleaseSecExecuterECGROUP(void)
{
  Log(kDot2LogLevel_Event, "Release sec executer EC group\n");
  if (g_dot2_mib.sec_executer.ossl.ecg) {
    EC_GROUP_clear_free(g_dot2_mib.sec_executer.ossl.ecg);
    g_dot2_mib.sec_executer.ossl.ecg = NULL;
  }
}


/**
 * @brief Openssl 보안연산실행자를 초기화한다.
 * @param[in] interval 서명파라미터 계산주기
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_InitSecExecuter(Dot2SigningParamsPrecomputeInterval interval)
{
  Log(kDot2LogLevel_Event, "Initialize openssl security executer\n");

  /*
   * 타원곡선그룹 정보를 초기화한다.
   */
  int ret = dot2_ossl_InitSecExecuterECGROUP();
  if (ret < 0) {
    Err("Fail to initialize openssl security executer");
    return ret;
  }

  /*
   * 서명파라미터계산기능을 초기화한다.
   */
  if (interval != kDot2SigningParamsPrecomputeInterval_NotUse) {
    g_dot2_mib.sec_executer.ossl.use_sign_parms_precompute = true;
    ret = dot2_ossl_InitSigningParametersComputeFunction(interval);
  }
  return ret;
}


/**
 * @brief Openssl 보안연산실행자를 해제한다.
 */
void INTERNAL dot2_ossl_ReleaseSecExecuter(void)
{
  Log(kDot2LogLevel_Event, "Release openssl security executer\n");
  struct Dot2OsslSigningParametersList *list = &(g_dot2_mib.sec_executer.ossl.sign_params_list);

  /*
   * 서명파라미터 사전계산 쓰레드를 종료시킨다.
   */
  if (g_dot2_mib.sec_executer.ossl.use_sign_parms_precompute) {
    if (list->thread_running) {
      list->thread_running = false;
      pthread_join(list->thread, NULL);
    }
  }

  /*
   * 서명파라미터 리스트와 보안연산자를 해제한다.
   */
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  if (g_dot2_mib.sec_executer.ossl.use_sign_parms_precompute) {
    g_dot2_mib.sec_executer.ossl.use_sign_parms_precompute = false;
    dot2_ossl_FlushSigningParametersList(list);
  }
  dot2_ossl_ReleaseSecExecuterECGROUP();
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
}
