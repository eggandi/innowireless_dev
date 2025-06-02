/** 
 * @file
 * @brief Openssl 기반 키 관련 기능 구현 파일
 * @date 2020-09-26
 * @author gyun
 */


// 의존 라이브러리 헤더
#include "openssl/ec.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-2016/dot2-types.h"


/**
 * @brief EC_KEY 정보를 할당한다(키값은 생성되지 않는다).
 * @param[in] ecg 타원곡선그룹정보
 * @return 할당된 EC_KEY 정보 포인터 (호출자는 사용 후 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 할당 실패
 */
EC_KEY INTERNAL * dot2_ossl_AllocateECKEY(EC_GROUP *ecg)
{
  EC_KEY *eck = EC_KEY_new();
  if (eck) {
    if (EC_KEY_set_group(eck, (const EC_GROUP *)ecg) == DOT2_OSSL_FAIL) {
      EC_KEY_free(eck);
      eck = NULL;
    }
  }
  return eck;
}


/**
 * @brief 키쌍을 담은 EC_KEY 정보를 생성한다.
 * @param[in] ecg 타원곡선그룹정보
 * @return 생성된 EC_KEY 정보 포인터 (호출자는 사용 후 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 생성 실패
 */
EC_KEY INTERNAL * dot2_ossl_GenerateECKEY(EC_GROUP *ecg)
{
  EC_KEY *eck = dot2_ossl_AllocateECKEY(ecg);
  if (eck) {
    if (EC_KEY_generate_key(eck) == DOT2_OSSL_FAIL) {
      EC_KEY_free(eck);
      eck = NULL;
    }
  }
  return eck;
}


/**
 * @brief (개인키가 저장된) EC_KEY 정보로부터 개인키바이트열을 얻는다.
 * @param[in] eck_priv_key (개인키가 저장된) EC_KEY 정보
 * @param[out] priv_key 개인키바이트열이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GetPrivKeyOctsFromECKEY(EC_KEY *eck_priv_key, struct Dot2ECPrivateKey *priv_key)
{
  int ret = -kDot2Result_OSSL_GetPrivKeyOctsFromECKEY;
  const BIGNUM *bn_priv_key = EC_KEY_get0_private_key(eck_priv_key);
  if (bn_priv_key) {
    if (BN_bn2binpad(bn_priv_key, priv_key->octs, DOT2_EC_256_KEY_LEN) == DOT2_EC_256_KEY_LEN) {
      ret = kDot2Result_Success;
    }
  }
  return ret;
}


/**
 * @brief 개인키 바이트열로부터 개인키를 포함한 EC_KEY 정보를 생성한다.
 * @param[in] priv_key 개인키 바이트열
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 실패
 */
EC_KEY INTERNAL * dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(struct Dot2ECPrivateKey *priv_key, int *err)
{
  BIGNUM *bn_priv_key = NULL;
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  int key_size = DOT2_EC_256_KEY_LEN;

  /*
   * EC_KEY 정보를 생성하고 개인키를 저장한다.
   */
  int ret = -kDot2Result_NoMemory;
  EC_KEY *eck_priv_key = dot2_ossl_AllocateECKEY(ecg);
  if (eck_priv_key) {
    ret = kDot2Result_Success;
    if (((bn_ctx = BN_CTX_new()) == NULL) ||
        ((bn_priv_key = BN_bin2bn(priv_key->octs, key_size, NULL)) == NULL) ||
        (EC_KEY_set_private_key(eck_priv_key, bn_priv_key) == DOT2_OSSL_FAIL)) {
      EC_KEY_free(eck_priv_key);
      eck_priv_key = NULL;
      ret = -kDot2Result_OSSL_MakeECKEYPrivKeyFromPrivKeyOcts;
    }
  }

  if (bn_priv_key) { BN_free(bn_priv_key); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  *err = ret;
  return eck_priv_key;
}


/**
 * @brief BIGNUM 형식 개인키로부터 개인키를 포함한 EC_KEY 정보를 생성한다.
 * @param[in] bn_priv_key BIGNUM 형식 개인키
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 실패
 */
EC_KEY INTERNAL * dot2_ossl_MakeECKEYPrivKeyFromBIGNUMPrivKey(BIGNUM *bn_priv_key, int *err)
{
  int ret = -kDot2Result_NoMemory;
  EC_KEY *eck_priv_key = dot2_ossl_AllocateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
  if (eck_priv_key) {
    ret = kDot2Result_Success;
    if (EC_KEY_set_private_key(eck_priv_key, bn_priv_key) == DOT2_OSSL_FAIL) {
      EC_KEY_free(eck_priv_key);
      eck_priv_key = NULL;
      ret = -kDot2Result_OSSL_MakeECKEYPrivKeyFromBIGNUMPrivKey;
    }
  }
  *err = ret;
  return eck_priv_key;
}


#if 0 // NOTE:: 사용되지 않음
/**
 * @brief 개인키 바이트열로부터 개인키/공개키를 포함한 EC_KEY 정보를 생성한다.
 * @param[in] priv_key 개인키 바이트열
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 변환 실패
 */
EC_KEY INTERNAL * dot2_ossl_MakeECKEYPairFromPrivKeyOcts(struct Dot2ECPrivateKey *priv_key, int *err)
{
  BIGNUM *bn_priv_key = NULL;
  EC_POINT *ecp_pub_key = NULL;
  const EC_POINT *ecp_G = NULL;
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  int key_size = DOT2_EC_256_KEY_LEN;

  /*
   * EC_KEY 정보를 생성한다.
   */
  int ret = -kDot2Result_NoMemory;
  EC_KEY *eck_pair = dot2_ossl_AllocateECKEY(ecg);
  if (eck_pair) {
    /*
     * EC_KEY 정보에 개인키를 저장한다.
     * 개인키로부터 공개키를 계산하여 EC_KEY 정보에 저장한다.
     *  - A = a * G
     *  - A: public key, a: private key, G: generator
     */
    ret = kDot2Result_Success;
    if (((bn_ctx = BN_CTX_new()) == NULL) ||
        ((bn_priv_key = BN_bin2bn(priv_key->octs, key_size, NULL)) == NULL) ||
        (EC_KEY_set_private_key(eck_pair, bn_priv_key) == DOT2_OSSL_FAIL) ||
        ((ecp_pub_key = EC_POINT_new(ecg)) == NULL) ||
        ((ecp_G = EC_GROUP_get0_generator(ecg)) == NULL) ||
        (EC_POINT_mul(ecg, ecp_pub_key, 0, ecp_G, bn_priv_key, bn_ctx) == DOT2_OSSL_FAIL) ||
        (EC_KEY_set_public_key(eck_pair, ecp_pub_key) == DOT2_OSSL_FAIL)) {
      EC_KEY_free(eck_pair);
      eck_pair = NULL;
      ret = -kDot2Result_OSSL_MakeECKEYPairFromPrivKeyOcts;
    }
  }

  if (bn_priv_key) { BN_free(bn_priv_key); }
  if (ecp_pub_key) { EC_POINT_free(ecp_pub_key); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  *err = ret;
  return eck_pair;
}
#endif


#if 0 // NOTE:: 사용되지 않음
/**
 * @brief 비압축 공개키바이트열로부터 공개키를 포함한 EC_KEY 정보를 생성한다.
 * @param[in] pub_key 비압축 공개키바이트열
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 변환 실패
 */
EC_KEY INTERNAL * dot2_ossl_MakeECKEYfromUncompressedPubKeyOcts(struct Dot2ECPublicKey *pub_key)
{
  BIGNUM *bn_x = NULL, *bn_y = NULL;
  EC_KEY *ec_key = dot2_ossl_AllocateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
  if (ec_key) {
    if (((bn_x = BN_bin2bn(pub_key->u.point.u.xy.x, DOT2_EC_256_KEY_LEN, NULL)) == NULL) ||
        ((bn_y = BN_bin2bn(pub_key->u.point.u.xy.y, DOT2_EC_256_KEY_LEN, NULL)) == NULL) ||
        (EC_KEY_set_public_key_affine_coordinates(ec_key, bn_x, bn_y) == DOT2_OSSL_FAIL)) {
      EC_KEY_free(ec_key);
      ec_key = NULL;
    }
  }
  if (bn_x) { BN_free(bn_x); }
  if (bn_y) { BN_free(bn_y); }
  return ec_key;
}
#endif

/**
 * @brief 압축형식 타원곡선좌표 바이트열로부터 EC_POINT 정보를 생성한다.
 * @param[in] point 압축형식 좌표 바이트열
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_POINT 정보 포인터 (호출자는 나중에 EC_POINT_free()로 해제해 줘야 한다)
 * @retval NULL: 생성 실패
 */
EC_POINT INTERNAL * dot2_ossl_MakeECPOINTfromCompressedPointOcts(const struct Dot2ECPoint *point, int *err)
{
  BIGNUM *bn_x = NULL;
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  EC_POINT *ecp = EC_POINT_new(ecg);
  if (ecp) {
    int y_bit = (point->u.point.form == kDot2ECPointForm_Compressed_y_0) ? 0 : 1;
    if (((bn_ctx = BN_CTX_new()) == NULL) ||
        ((bn_x = BN_bin2bn(point->u.point.u.xy.x, DOT2_EC_256_KEY_LEN, NULL)) == NULL) ||
        (EC_POINT_set_compressed_coordinates(ecg, ecp, bn_x, y_bit, bn_ctx) == DOT2_OSSL_FAIL)) {
      EC_POINT_free(ecp);
      ecp = NULL;
      *err = -kDot2Result_OSSL_MakeECPOINTfromCompressedPointOcts;
    }
  }
  if (bn_x) { BN_free(bn_x); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  return ecp;
}


/**
 * @brief 압축형식 타원곡선좌표 바이트열로부터 EC_POINT 정보를 생성한다.
 * @param[in] point 압축형식 좌표 바이트열
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_POINT 정보 포인터 (호출자는 나중에 EC_POINT_free()로 해제해 줘야 한다)
 * @retval NULL: 생성 실패
 */
EC_POINT INTERNAL * dot2_ossl_MakeECPOINTfromUncompressedPointOcts(const struct Dot2ECPoint *point, int *err)
{
  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  BN_CTX *bn_ctx = NULL;
  EC_POINT *ecp = NULL;
  if ((bn_ctx = BN_CTX_new()) &&
      (ecp = EC_POINT_new(ecg)) &&
      (EC_POINT_oct2point(ecg, ecp, point->u.octs, sizeof(point->u.octs), bn_ctx) == DOT2_OSSL_SUCCESS)) {
    BN_CTX_free(bn_ctx);
    *err = kDot2Result_Success;
    return ecp;
  }
  if (ecp) { EC_POINT_free(ecp); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  *err = -kDot2Result_OSSL_MakeECPOINTfromUncompressedPointOcts;
  return NULL;
}


/**
 * @brief 타원곡선좌표 바이트열로부터 EC_POINT 정보를 생성한다.
 * @param[in] point 좌표 바이트열
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_POINT 정보 포인터 (호출자는 나중에 EC_POINT_free()로 해제해 줘야 한다)
 * @retval NULL: 생성 실패
 */
EC_POINT INTERNAL * dot2_ossl_MakeECPOINTfromPointOcts(const struct Dot2ECPoint *point, int *err)
{
  if (point->u.point.form == kDot2ECPointForm_Uncompressed) {
    return dot2_ossl_MakeECPOINTfromUncompressedPointOcts(point, err);
  } else {
    return dot2_ossl_MakeECPOINTfromCompressedPointOcts(point, err);
  }
}


/**
 * @brief EC_POINT 형식 공개키로부터 공캐키를 포함한 EC_KEY 정보를 생성한다.
 * @param[in] ecp_pub_key BIGNUM 형식 공개키
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 실패
 */
EC_KEY INTERNAL * dot2_ossl_MakeECKEYPubKeyFromECPOINTPubKey(const EC_POINT *ecp_pub_key)
{
  EC_KEY *eck_pub_key = dot2_ossl_AllocateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
  if (eck_pub_key) {
    if (EC_KEY_set_public_key(eck_pub_key, ecp_pub_key) == DOT2_OSSL_FAIL) {
      EC_KEY_free(eck_pub_key);
      eck_pub_key = NULL;
    }
  }
  return eck_pub_key;
}

#if 0 // NOTE:: 사용되지 않음
/**
 * @brief 압축형식 공개키 바이트열로부터 공개키를 포함한 EC_KEY 정보를 생성한다.
 * @param[in] pub_key 압축형식 공개키 바이트열
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 변환 실패
 */
EC_KEY INTERNAL * dot2_ossl_MakeECKEYfromCompressedPubKeyOcts(struct Dot2ECPublicKey *pub_key, int *err)
{
  EC_POINT *ecp_pub_key = NULL;
  EC_KEY *ec_key = dot2_ossl_AllocateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
  if (ec_key) {
    if (((ecp_pub_key = dot2_ossl_MakeECPOINTfromCompressedPointOcts(pub_key, err)) == NULL) ||
        (EC_KEY_set_public_key(ec_key, ecp_pub_key) == DOT2_OSSL_FAIL)) {
      EC_KEY_free(ec_key);
      ec_key = NULL;
      *err = -kDot2Result_OSSL_MakeECKEYfromCompressedPubKeyOcts;
    }
  }
  if (ecp_pub_key) { EC_POINT_free(ecp_pub_key); }
  return ec_key;
}
#endif


/**
 * @brief 공개키 바이트열로부터 공개키를 포함한 EC_KEY 정보를 생성한다.
 * @param[in] pub_key 공개키 바이트열
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 변환 실패
 */
EC_KEY INTERNAL * dot2_ossl_MakeECKEYfromPubKeyOcts(const struct Dot2ECPublicKey *pub_key, int *err)
{
  EC_POINT *ecp_pub_key = NULL;
  EC_KEY *ec_key = dot2_ossl_AllocateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
  if (ec_key) {
    if (((ecp_pub_key = dot2_ossl_MakeECPOINTfromPointOcts(pub_key, err)) == NULL) ||
        (EC_KEY_set_public_key(ec_key, ecp_pub_key) == DOT2_OSSL_FAIL)) {
      EC_KEY_free(ec_key);
      ec_key = NULL;
      *err = -kDot2Result_OSSL_MakeECKEYfromCompressedPubKeyOcts;
    }
  }
  if (ecp_pub_key) { EC_POINT_free(ecp_pub_key); }
  return ec_key;
}


/**
 * @brief EC_POINT 형식의 포인트로부터 포인트 바이트열을 얻는다.
 * @param ecp EC_POINT 형식의 포인트
 * @param point 포인트 바이트열이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GetUncompressedPointOctsFromECPOINT(const EC_POINT *ecp, struct Dot2ECPoint *point)
{
  int ret = -kDot2Result_OSSL_GetUncompressedPointOctsFromECPOINT;
  BN_CTX *bn_ctx = BN_CTX_new();
  if (bn_ctx) {
    int ret1 = (int)EC_POINT_point2oct(g_dot2_mib.sec_executer.ossl.ecg,
                                       ecp,
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       point->u.octs,
                                       DOT2_EC_256_PUB_KEY_LEN,
                                       bn_ctx);
    if (ret1 == DOT2_EC_256_PUB_KEY_LEN) {
      ret = kDot2Result_Success;
    }
    BN_CTX_free(bn_ctx);
  }
  return ret;
}


/**
 * @brief (공개키가 저장된) EC_KEY 정보로부터 비압축 공개키바이트열을 얻는다.
 * @param[in] eck_pub_key (공개키가 저장된) EC_KEY 정보
 * @param[out] pub_key 공개키바이트열이 저장된다.
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_GetUncompressedPubKeyOctsFromECKEY(EC_KEY *eck_pub_key, struct Dot2ECPublicKey *pub_key)
{
  int ret = -kDot2Result_OSSL_GetUncompressedPubKeyOctsFromECKEY;
  const EC_POINT *ec_pub_key = EC_KEY_get0_public_key(eck_pub_key);
  if (ec_pub_key) {
    ret = dot2_ossl_GetUncompressedPointOctsFromECPOINT(ec_pub_key, pub_key);
  }
  return ret;
}


/**
 * @brief 압축형식 공개키 바이트열로부터 공개키를 포함한 EC_KEY 정보와 비압축형식 공개키 바이트열을 생성한다.
 * @param[in] pub_key 압축형식 공개키 바이트열
 * @param[out] pub_key_uncomp 비압축형식 공개키 바이트열이 저장될 버퍼 포인터
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return EC_KEY 정보 포인터 (호출자는 나중에 EC_KEY_free()로 해제해 줘야 한다)
 * @retval NULL: 변환 실패
 */
EC_KEY INTERNAL *dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(
  const struct Dot2ECPublicKey *pub_key,
  struct Dot2ECPublicKey *pub_key_uncomp,
  int *err)
{
  /*
   * 압축형식 공개키 바이트열로부터 EC_KEY를 생성한 후, EC_KEY로부터 비압축형식 공개키 바이트열을 얻는다.
   */
  EC_KEY *eck = dot2_ossl_MakeECKEYfromPubKeyOcts(pub_key, err);
  if (eck) {
    *err = dot2_ossl_GetUncompressedPubKeyOctsFromECKEY(eck, pub_key_uncomp);
    if (*err < 0) {
      EC_KEY_free(eck);
      eck = NULL;
    }
  }
  return eck;
}


#if 0 // NOTE:: 사용되지 않음
/**
 * @brief BIGNUM 형식의 개인키와 쌍을 이루는 EC_POINT 형식 공개키를 생성한다.
 * @param[in] bn_priv_key BIGNUM 형식의 개인키
 * @return EC_POINT 형식 공개키
 * @retval NULL: 실패
 */
EC_POINT * dot2_ossl_MakeECPOINTPubKeyFromBIGNUMPrivKey(BIGNUM *bn_priv_key)
{
  /*
   * 개인키로부터 공개키를 계산한다.
   *  - A = a * G
   *  - A: public key, a: private key, G: generator
   */
  BN_CTX *bn_ctx = NULL;
  EC_POINT *ecp_pub_key = NULL;
  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  const EC_POINT *ecp_G = NULL;

  if ((bn_ctx = BN_CTX_new()) &&
      (ecp_pub_key = EC_POINT_new(ecg)) &&
      (ecp_G = EC_GROUP_get0_generator(ecg)) &&
      (EC_POINT_mul(ecg, ecp_pub_key, 0, ecp_G, bn_priv_key, bn_ctx) == DOT2_OSSL_SUCCESS)) {
    BN_CTX_free(bn_ctx);
    return ecp_pub_key;
  }

  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  if (ecp_pub_key) { EC_POINT_free(ecp_pub_key); }
  return NULL;
}
#endif


/**
 * @brief EC_KEY 형식의 개인키와 공개키가 유효한 쌍을 이루는지 확인한다.
 * @param[in] eck_priv_key EC_KEY 형식의 개인키
 * @param[in] eck_pub_key EC_KEY 형식의 공개키
 * @return 유효한 쌍을 이루는지 여부
 *
 * NOTE:: eck_priv_key 정보 내 공개키 정보가 eck_pub_key로 업데이트된다.
 */
bool dot2_ossl_CheckECKEYKeyPair(EC_KEY *eck_priv_key, const EC_KEY *eck_pub_key)
{
  const EC_POINT *ecp_pub_key = NULL;
  if ((ecp_pub_key = EC_KEY_get0_public_key(eck_pub_key)) &&
      (EC_KEY_set_public_key(eck_priv_key, ecp_pub_key) == DOT2_OSSL_SUCCESS) &&
      (EC_KEY_check_key(eck_priv_key) == DOT2_OSSL_SUCCESS)) {
    return true;
  }
  return false;
}
