/** 
 * @file
 * @brief openssl 키 생성 관련 구현
 * @date 2020-03-10
 * @author gyun
 */



// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief 개인키/공개키 키쌍 바이트열을 생성한다.
 * @param[out] key_pair 생성된 키쌍 바이트열이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GenerateECKeyPairOcts(struct Dot2ECKeyPairOcts *key_pair)
{
  Log(kDot2LogLevel_Event, "Generate EC key pair octs\n");
  EC_KEY *eck_key_pair = NULL;
  int ret = -kDot2Result_OSSL_GenerateECKEY;
  eck_key_pair = dot2_ossl_GenerateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
  if (eck_key_pair) {
    ret = dot2_ossl_GetPrivKeyOctsFromECKEY(eck_key_pair, &(key_pair->priv_key));
    if (ret == kDot2Result_Success) {
      ret = dot2_ossl_GetUncompressedPubKeyOctsFromECKEY(eck_key_pair, &(key_pair->pub_key));
    }
  }
  if (eck_key_pair) {
    EC_KEY_free(eck_key_pair);
  }
  return ret;
}


/**
 * @brief 개인키/공개키 키쌍 정보(바이트열 및 EC_KEY)를 생성한다.
 * @param[out] key_pair 생성된 키쌍 정보(바이트열 및 EC_KEY) 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GenerateECKeyPair(struct Dot2ECKeyPair *key_pair)
{
  Log(kDot2LogLevel_Event, "Generate EC key pair octs\n");
  int ret = -kDot2Result_OSSL_GenerateECKEY;
  key_pair->eck = dot2_ossl_GenerateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
  if (key_pair->eck) {
    ret = dot2_ossl_GetPrivKeyOctsFromECKEY(key_pair->eck, &(key_pair->octs.priv_key));
    if (ret == kDot2Result_Success) {
      ret = dot2_ossl_GetUncompressedPubKeyOctsFromECKEY(key_pair->eck, &(key_pair->octs.pub_key));
    }
  }
  if ((ret < 0) &&
      (key_pair->eck)) {
    EC_KEY_free(key_pair->eck);
  }
  return ret;
}
