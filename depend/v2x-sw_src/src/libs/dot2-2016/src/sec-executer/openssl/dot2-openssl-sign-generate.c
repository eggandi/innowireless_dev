/**
 * @file
 * @brief OpenSSL 기반 서명 생성 관련 구현
 * @date 2020-04-11
 * @author gyun
 */


// 시스템 헤더파일
#include <unistd.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-openssl-inline.h"


/**
 * @brief 리스트 내에서 이번에 사용할 서명파라미터를 얻고, 다음번 서명 파라미터를 지정한다.
 * @param[in] list 서명파라미터 리스트
 * @return 사용할 서명파라미터 포인터
 */
static inline struct Dot2OsslSigningParameters *
dot2_ossl_GetAndUpdateCurrentSigningParameters(struct Dot2OsslSigningParametersList *list)
{
  if (list->current) {
    if (list->current == TAILQ_LAST(&(list->head), Dot2OsslSigningParametersHead)) {
      list->current = TAILQ_FIRST(&(list->head));
    } else {
      list->current = TAILQ_NEXT(list->current, entries);
    }
  } else {
    list->current = TAILQ_FIRST(&(list->head));
  }
  return list->current;
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
 * @brief 서명에 사용할 파라미터 정보를 리스트에서 가져온다.
 * @param[in] list 서명 파라미터 리스트
 * @param[out] bn_r r 값이 반환될 변수 포인터 (호출자는 사용 후 BN_free()해 주어야 한다)
 * @param[out] bn_kinv k^-1 값이 반환될 변수 포인터 (호출자는 사용 후 BN_free()해 주어야 한다)
 * @param[out] R R 값이 반환될 변수 포인터
 */
static inline void dot2_ossl_GetSigningParameters(
  struct Dot2OsslSigningParametersList *list,
  BIGNUM **bn_r,
  BIGNUM **bn_kinv,
  struct Dot2ECPoint *R)
{
  *bn_r = NULL;
  *bn_kinv = NULL;
  struct Dot2OsslSigningParameters *current = dot2_ossl_GetAndUpdateCurrentSigningParameters(list);
  if (current) {
    *bn_r = BN_dup(list->current->bn_r);
    *bn_kinv = BN_dup(list->current->bn_kinv);
    memcpy(R, &(list->current->R), sizeof(struct Dot2ECPoint));
    list->consume_cnt = dot2_ossl_IncreaseSigningParametersConsumeCnt(list->consume_cnt);
  }
}


/**
 * @brief 서명을 생성한다.
 * @param[in] form 생성될 서명의 형식
 * @param[in] tbs 서명계산을 위해 사용되는 ToBeSignedData 또는 ToBeSignedCert 인코딩 데이터
 * @param[in] tbs_size tbs 데이터의 길이
 * @param[in] signer_h 서명인증서에 대한 해시 (NULL 가능)
 * @param[in] key 서명 생성용 개인키가 담긴 키쌍 정보
 * @param[out] sign 생성된 서명이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GenerateSignature(
  Dot2ECPointForm form,
  const uint8_t *tbs,
  size_t tbs_size,
  const struct Dot2SHA256 *signer_h,
  EC_KEY *eck_priv_key,
  struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Generate signature - form: %u\n", form);

  /*
   * 서명 계산에 입력될 해시값을 계산한다.
   */
  struct Dot2SHA256 h_input;
  dot2_ossl_CalculateSignatureHashInput(tbs, tbs_size, signer_h, &h_input);

  BIGNUM *bn_r = NULL, *bn_kinv = NULL;
  struct Dot2ECPoint *R = NULL, tmp_R;
  if (g_dot2_mib.sec_executer.ossl.use_sign_parms_precompute) {
    pthread_mutex_lock(&(g_dot2_mib.mtx));
    dot2_ossl_GetSigningParameters(&(g_dot2_mib.sec_executer.ossl.sign_params_list), &bn_r, &bn_kinv, &tmp_R);
    pthread_mutex_unlock(&(g_dot2_mib.mtx));
    R = &tmp_R;
  }

  /*
   * 서명을 생성한다.
   */
  int ret;
  if (form == kDot2ECPointForm_X_only) {
    ret = dot2_ossl_GenerateXonlySignature(&h_input, eck_priv_key, bn_r, bn_kinv, sign);
  } else {
    ret = dot2_ossl_GenerateUncompressedSignature(&h_input, eck_priv_key, R, bn_r, bn_kinv, sign);
    if ((form == kDot2ECPointForm_Compressed) ||
        (form == kDot2ECPointForm_Compressed_y_0) ||
        (form == kDot2ECPointForm_Compressed_y_1)) {
      dot2_ossl_CompresssSignature(sign);
    }
  }

  if (bn_r) { BN_free(bn_r); }
  if (bn_kinv) { BN_free(bn_kinv); }

  return ret;
}


/**
 * @brief ECDSA_SIG 형식의 서명으로부터 서명바이트열을 얻는다.
 * @param[in] sig ECDSA_SIG 형식의 서명 데이터
 * @param[out] sign 바이트열 형식의 서명이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ossl_GetSignatureOctsFromECDSASIG(const ECDSA_SIG *sig, struct Dot2Signature *sign)
{
  uint8_t *r = sign->R_r.u.point.u.xy.x;
  uint8_t *s = sign->s;
  int key_size = DOT2_EC_256_KEY_LEN;
  const BIGNUM *bn_r, *bn_s;
  int ret = -kDot2Result_OSSL_GetSignatureOctsFromECDSASIG;
  if (((bn_r = ECDSA_SIG_get0_r(sig)) != NULL) &&
      ((bn_s = ECDSA_SIG_get0_s(sig)) != NULL) &&
      (BN_bn2binpad(bn_r, r, key_size) == key_size) &&
      (BN_bn2binpad(bn_s, s, key_size) == key_size)) {
    ret = kDot2Result_Success;
  }
  return ret;
}


/**
 * @brief X-only 서명을 생성한다.
 * @param[in] h_input 서명생성 연산에 사용되는 해시입력 (= H(tbs) || H(signer))
 * @param[in] eck_priv_key 서명용 개인키 (EC_KEY 형식)
 * @param[in] bn_r 사전에 계산된 BIGNUM 형식 r 값 (사전계산된 값이 없을 경우 NULL 전달 -> ECDSA_do_sign() 내에서 계산된다)
 * @param[in] bn_kinv 사전에 계산된 BIGNUM 형식 k^-1 값 (사전계산된 값이 없을 경우 NULL 전달 -> ECDSA_do_sign() 내에서 계산된다)
 * @param[out] sign 생성된 서명이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GenerateXonlySignature(
  const struct Dot2SHA256 *h_input,
  EC_KEY *eck_priv_key,
  BIGNUM *bn_r,
  BIGNUM *bn_kinv,
  struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Generate x-only signature octs\n");

  /*
   * 서명 유형을 x-only로 지정
   */
  sign->R_r.u.point.form = kDot2ECPointForm_X_only;

  /*
   * ECDSA_SIG 형식의 서명을 생성한 후 바이트열 형식으로 변환한다.
   */
  ECDSA_SIG *ecdsa_sig;
  int ret = -kDot2Result_OSSL_ECDSA_do_sign;
  if (bn_r && bn_kinv) {
    ecdsa_sig = ECDSA_do_sign_ex(h_input->octs, DOT2_EC_256_KEY_LEN, bn_kinv, bn_r, eck_priv_key);
  } else {
    ecdsa_sig = ECDSA_do_sign(h_input->octs, DOT2_EC_256_KEY_LEN, eck_priv_key);
  }
  if (ecdsa_sig) {
    ret = dot2_ossl_GetSignatureOctsFromECDSASIG(ecdsa_sig, sign);
    ECDSA_SIG_free(ecdsa_sig);
  }
  return ret;
}


/**
 * @brief Uncompressed 서명을 생성한다.
 * @param[in] h_input 서명 연산에 사용되는 해시 입력
 * @param[in] eck_priv_key 서명용 개인키 (EC_KEY 형식)
 * @param[in] R_in 사전에 계산된 바이트열 형식 R 값 (사전계산된 값이 없을 경우 NULL 전달 -> 본 함수 내에서 계산된다)
 * @param[in] bn_r_in 사전에 계산된 BIGNUM 형식 r 값 (사전계산된 값이 없을 경우 NULL 전달 -> 본 함수 내에서 계산된다)
 * @param[in] bn_kinv_in 사전에 계산된 BIGNUM 형식 K^-1 값(사전계산된 값이 없을 경우 NULL 전달 -> 본 함수 내에서 계산된다)
 * @param[out] sign 생성된 서명이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GenerateUncompressedSignature(
  const struct Dot2SHA256 *h_input,
  EC_KEY *eck_priv_key,
  struct Dot2ECPoint *R_in,
  BIGNUM *bn_r_in,
  BIGNUM *bn_kinv_in,
  struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Generate uncompressed signature\n");

  /*
   * 서명 유형을 Uncompressed로 지정
   */
  sign->R_r.u.point.form = kDot2ECPointForm_Uncompressed;

  /*
   * R, r, K^-1 파라미터 중 하나라도 전달되지 않으면(=NULL이면) 계산한다.
   */
  int ret;
  bool precomputed;
  BIGNUM *bn_r;
  BIGNUM *bn_kinv;
  struct Dot2ECPoint *R;
  struct Dot2OsslSigningParameters sign_params;
  if ((bn_r_in == NULL) ||
      (bn_kinv_in == NULL) ||
      (R_in == NULL)) {
    ret = dot2_ossl_ComputeSigningParameters(&sign_params);
    if(ret < 0) {
      return ret;
    }
    bn_r = sign_params.bn_r;
    bn_kinv = sign_params.bn_kinv;
    R = &(sign_params.R);
    precomputed = false;
  } else {
    bn_r = bn_r_in;
    bn_kinv = bn_kinv_in;
    R = R_in;
    precomputed = true;
  }

  /*
   * s를 계산한 후, 반환변수에 R과 s를 저장한다.
   */
  BIGNUM *bn_z = NULL;
  BIGNUM *bn_s = NULL;
  const BIGNUM *bn_d;
  int key_size = DOT2_EC_256_KEY_LEN;
  ret = -kDot2Result_OSSL_ComputeSignatureS;
  if (((bn_z = BN_bin2bn(h_input->octs, key_size, NULL)) != NULL) &&
      ((bn_d = EC_KEY_get0_private_key(eck_priv_key)) != NULL) &&
      ((bn_s = dot2_ossl_GenerateSignature_s(bn_z, bn_r, bn_d, bn_kinv)) != NULL) &&
      (BN_bn2binpad(bn_s, sign->s, key_size) == key_size)) {
    memcpy(&(sign->R_r), R, sizeof(struct Dot2ECPoint));
    ret = kDot2Result_Success;
  }

  if (precomputed == false) {
    BN_free(bn_r);
    BN_free(bn_kinv);
  }
  if (bn_z) { BN_free(bn_z); }
  if (bn_s) { BN_free(bn_s); }
  return ret;
}


/**
 * @brief 서명 s 값을 생성하여 반환한다.
 * @param[in] bn_z 서명연산입력 : leftmost bits of H(H(tbs) || H(signer_id))
 * @param[in] bn_r 서명연산입력 : Rx mod n
 * @param[in] bn_d 서명연산입력 : 개인키
 * @param[in] bn_kinv 서명연산입력 : k^-1
 * @return 생성된 서명 s 포인터 (BIGNUM 형식)
 * @retval NULL: 실패
 *
 * s를 구하는 계산식은 다음과 같다.
 *  - s = (k^-1 * (z + (r * d))) mod n
 */
BIGNUM INTERNAL *
dot2_ossl_GenerateSignature_s(const BIGNUM *bn_z, const BIGNUM *bn_r, const BIGNUM *bn_d, const BIGNUM *bn_kinv)
{
  BIGNUM *bn_rd = NULL, *bn_zrd = NULL, *bn_s = NULL;
  BN_CTX *bn_ctx = NULL;
  const BIGNUM *bn_order = EC_GROUP_get0_order(g_dot2_mib.sec_executer.ossl.ecg);

  if (((bn_ctx = BN_CTX_new()) != NULL) &&
      ((bn_rd = BN_new()) != NULL) &&
      ((bn_zrd = BN_new()) != NULL) &&
      ((bn_s = BN_new()) != NULL))
  {
    if ((BN_mul(bn_rd, bn_r, bn_d, bn_ctx) == DOT2_OSSL_FAIL) || // r*d
        (BN_add(bn_zrd, bn_z, bn_rd) == DOT2_OSSL_FAIL) || // z + (r*d)
        (BN_mod_mul(bn_s, bn_kinv, bn_zrd, bn_order, bn_ctx) == DOT2_OSSL_FAIL)) { // s = (k^1 * (z + (r*d))) mod n
      BN_free(bn_s);
      bn_s = NULL;
    }
  }
  if (bn_rd) { BN_free(bn_rd); }
  if (bn_zrd) { BN_free(bn_zrd); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  return bn_s;
}


/**
 * @brief 비압축형식 서명을 압축한다.
 * @param[in/out] 서명정보
 */
void INTERNAL dot2_ossl_CompresssSignature(struct Dot2Signature *sign)
{
  if (sign->R_r.u.point.u.xy.y[DOT2_EC_256_KEY_LEN - 1] & 1U) {
    sign->R_r.u.point.form = kDot2ECPointForm_Compressed_y_1;
  } else {
    sign->R_r.u.point.form = kDot2ECPointForm_Compressed_y_0;
  }
}


/**
 * @brief 서명 생성 시 사용되는 파라미터들을 계산하여 반환한다.
 * @param[out] params 계산된 파라미터들이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_ComputeSigningParameters(struct Dot2OsslSigningParameters *params)
{
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  BIGNUM *bn_kinv = NULL, *bn_k = NULL, *bn_r = NULL, *bn_Rx = NULL;
  EC_POINT *ecp_R = NULL;
  const BIGNUM *bn_order = EC_GROUP_get0_order(ecg);

  /*
   * 변수를 할당하고, 길이를 지정한다.
   */
  if (((bn_ctx = BN_CTX_new()) == NULL) ||
      ((bn_k = BN_new()) == NULL) ||
      ((bn_r = BN_new()) == NULL) ||
      ((bn_Rx = BN_new()) == NULL) ||
      ((ecp_R = EC_POINT_new(ecg)) == NULL) ||
      (bn_order == NULL)) {
    goto err;
  }
  int order_bits = BN_num_bits(bn_order);
  if ((BN_set_bit(bn_k, order_bits) == DOT2_OSSL_FAIL) ||
      (BN_set_bit(bn_r, order_bits) == DOT2_OSSL_FAIL) ||
      (BN_set_bit(bn_Rx, order_bits) == DOT2_OSSL_FAIL)) {
    goto err;
  }

  /*
   * R과 r을 계산한다.
   */
  do {
    // 랜덤 k 생성
    do {
      if (BN_priv_rand_range(bn_k, bn_order) == DOT2_OSSL_FAIL) {
        goto err;
      }
    } while (BN_is_zero(bn_k));

    // R(x,y) = k * generator 계산
    // r = Rx mod n 계산
    if ((EC_POINT_mul(ecg, ecp_R, bn_k, NULL, NULL, bn_ctx) == DOT2_OSSL_FAIL) || // R(x,y)
        (EC_POINT_get_affine_coordinates(ecg, ecp_R, bn_Rx, NULL, bn_ctx) == DOT2_OSSL_FAIL) || // Rx
        (BN_nnmod(bn_r, bn_Rx, bn_order, bn_ctx) == DOT2_OSSL_FAIL)) { // r
      goto err;
    }
  } while (BN_is_zero(bn_r));

  /*
   * (K^-1)을 계산한다.
   */
  do {
    bn_kinv = BN_mod_inverse(NULL, bn_k, bn_order, bn_ctx);
    if (bn_kinv == NULL) {
      goto err;
    }
  } while (BN_is_zero(bn_kinv));

  /*
   * 반환변수에 저장한다.
   */
  params->bn_r = bn_r;
  params->bn_kinv = bn_kinv;
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  size_t len = EC_POINT_point2oct(ecg, ecp_R, form, params->R.u.octs, DOT2_EC_256_SIGN_R_LEN, bn_ctx);
  if (len != DOT2_EC_256_SIGN_R_LEN) {
    goto err;
  }

  BN_free(bn_k);
  BN_free(bn_Rx);
  EC_POINT_free(ecp_R);
  BN_CTX_free(bn_ctx);
  return kDot2Result_Success;

err:
  if (bn_kinv) { BN_free(bn_kinv); }
  if (bn_k) { BN_free(bn_k); }
  if (bn_r) { BN_free(bn_r); }
  if (bn_Rx) { BN_free(bn_Rx); }
  if (ecp_R) { EC_POINT_free(ecp_R); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  return -kDot2Result_OSSL_ComputeSigningParameters;
}
