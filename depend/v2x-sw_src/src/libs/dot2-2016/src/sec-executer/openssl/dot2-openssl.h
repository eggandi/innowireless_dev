/** 
 * @file
 * @brief OpenSSL 관련 기능을 정의한 헤더 파일
 * @date 2020-04-11
 * @author gyun
 */


#ifndef V2X_SW_DOT2_OPENSSL_H
#define V2X_SW_DOT2_OPENSSL_H


// 라이브러리 의존 헤더 파일
#include "openssl/ec.h"
#include "sudo_queue.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-defines.h"
#include "dot2-internal-types.h"


/// Openssl API 수행 결과: 실패
#define DOT2_OSSL_FAIL (0)
/// Openssl API 수행 결과: 성공
#define DOT2_OSSL_SUCCESS (1)
/// 미리 계산해 두는 서명 파라미터 개수
#define DOT2_PRECOMPUTED_SIGN_PARAMS_NUM (10)


/**
 * @brief 서명 생성 시 사용되는 파라미터들
 */
struct Dot2OsslSigningParameters
{
  BIGNUM *bn_kinv; ///< K^-1
  BIGNUM *bn_r; ///< r = Rx mod n
  struct Dot2ECPoint R; ///< R(x,y) = k * G
  TAILQ_ENTRY(Dot2OsslSigningParameters) entries;
};
TAILQ_HEAD(Dot2OsslSigningParametersHead, Dot2OsslSigningParameters);


/**
 * @brief 서명 파라미터 리스트
 */
struct Dot2OsslSigningParametersList
{
  struct Dot2OsslSigningParametersHead head; ///< 파라미터 리스트 접근 변수
  struct Dot2OsslSigningParameters *current; ///< 이번에 사용한 서명 파라미터 엔트리
  unsigned int consume_cnt; ///< 사용된 파라미터 개수
  pthread_t thread; ///< 서명파라미터 업데이트 쓰레드
  bool thread_running; ///< 서명파라미터 업데이트 쓰레드 동작 여부
  Dot2SigningParamsPrecomputeInterval compute_interval; ///< 서명 파라미터 계산 주기(밀리초 단위) - 타이머 주기
};


/**
 * @brief Openssl 보안연산실행자 정보
 */
struct Dot2OsslSecExecuter
{
  EC_GROUP *ecg; ///< 타원곡선그룹
  bool use_sign_parms_precompute;
  struct Dot2OsslSigningParametersList sign_params_list; ///< 서명파라미터 리스트
};


#ifdef __cplusplus
extern "C" {
#endif


// dot2-openssl.c
int INTERNAL dot2_ossl_InitSecExecuter(Dot2SigningParamsPrecomputeInterval interval);
void INTERNAL dot2_ossl_ReleaseSecExecuter(void);

// dot2-openssl-key.c
EC_KEY INTERNAL * dot2_ossl_AllocateECKEY(EC_GROUP *ecg);
EC_KEY INTERNAL * dot2_ossl_GenerateECKEY(EC_GROUP *ecg);
int INTERNAL dot2_ossl_GetPrivKeyOctsFromECKEY(EC_KEY *eck_priv_key, struct Dot2ECPrivateKey *priv_key);
EC_KEY INTERNAL * dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(struct Dot2ECPrivateKey *priv_key, int *err);
EC_KEY INTERNAL * dot2_ossl_MakeECKEYPrivKeyFromBIGNUMPrivKey(BIGNUM *bn_priv_key, int *err);
EC_POINT INTERNAL * dot2_ossl_MakeECPOINTfromCompressedPointOcts(const struct Dot2ECPoint *point, int *err);
EC_POINT INTERNAL * dot2_ossl_MakeECPOINTfromPointOcts(const struct Dot2ECPoint *point, int *err);
EC_KEY INTERNAL * dot2_ossl_MakeECKEYPubKeyFromECPOINTPubKey(const EC_POINT *ecp_pub_key);
EC_KEY INTERNAL * dot2_ossl_MakeECKEYfromPubKeyOcts(const struct Dot2ECPublicKey *pub_key, int *err);
int INTERNAL dot2_ossl_GetUncompressedPointOctsFromECPOINT(const EC_POINT *ecp, struct Dot2ECPoint *point);
int INTERNAL dot2_ossl_GetUncompressedPubKeyOctsFromECKEY(EC_KEY *eck_pub_key, struct Dot2ECPublicKey *pub_key);
EC_KEY INTERNAL * dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(const struct Dot2ECPublicKey *pub_key, struct Dot2ECPublicKey *pub_key_uncomp, int *err);
bool dot2_ossl_CheckECKEYKeyPair(EC_KEY *eck_priv_key, const EC_KEY *eck_pub_key);

// dot2-openssl-key-generate.c
int INTERNAL dot2_ossl_GenerateECKeyPairOcts(struct Dot2ECKeyPairOcts *key_pair);
int INTERNAL dot2_ossl_GenerateECKeyPair(struct Dot2ECKeyPair *key_pair);

// dot2-openssl-linkage-value.c
int INTERNAL dot2_ossl_DeriveLinkageValue_j(uint8_t j, const uint8_t *la1_id, const uint8_t *la2_id, const uint8_t *ls1, const uint8_t *ls2, uint8_t *lv_j);

// dot2-openssl-reconstruct-priv-key.c
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPrivateKey_1(const struct Dot2ECPrivateKey *init_priv_key, const struct Dot2ECPrivateKey *recon_priv, const struct Dot2Cert *cert, const struct Dot2SHA256 *issuer_h, struct Dot2ECPrivateKey *priv_key, int *err);
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPrivateKey_2(const struct Dot2ECPrivateKey *init_priv_key, const struct Dot2ECPrivateKey *recon_priv, const struct Dot2SHA256 *tbs_cert_h, const struct Dot2SHA256 *issuer_h, struct Dot2ECPrivateKey *priv_key, int *err);
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPrivateKey_3(const struct Dot2ECPrivateKey *init_priv_key, const struct Dot2ECPrivateKey *recon_priv, const struct Dot2SHA256 *h_input, struct Dot2ECPrivateKey *priv_key, int *err);

// dot2-openssl-reconstruct-pub-key.c
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_1(const struct Dot2ECPublicKey *recon_pub, const struct Dot2Cert *cert, const struct Dot2SHA256 *issuer_h, const struct Dot2ECPublicKey *issuer_pub_key, struct Dot2ECPublicKey *pub_key, int *err);
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_2(const struct Dot2ECPublicKey *recon_pub, const struct Dot2SHA256 *tbs_cert_h, const struct Dot2SHA256 *issuer_h, const struct Dot2ECPublicKey *issuer_pub_key, struct Dot2ECPublicKey *pub_key, int *err);
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_3(const struct Dot2ECPublicKey *recon_pub, const struct Dot2SHA256 *h_input, const struct Dot2ECPublicKey *issuer_pub_key, struct Dot2ECPublicKey *pub_key, int *err);
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_4(const struct Dot2ECPublicKey *recon_pub, const struct Dot2SHA256 *h_input, const EC_POINT *ecp_issuer_pub_key, int *err);
int INTERNAL dot2_ossl_SignerPublicKeyReconstruction(struct Dot2SPDUProcessWork *work);

// dot2-openssl-reconstruct-sign-butterfly-key.c
int INTERNAL dot2_ossl_MakeSigningCocoonKeyPair(uint32_t i, uint32_t j, const struct Dot2AESKey *exp_key, const struct Dot2ECPrivateKey *seed_priv, struct Dot2ECKeyPairOcts *key_pair);
int INTERNAL dot2_ossl_MakeEncryptionCocoonKeyPair(uint32_t i, uint32_t j, const struct Dot2AESKey *exp_key, const struct Dot2ECPrivateKey *seed_priv, struct Dot2ECKeyPairOcts *key_pair);
int INTERNAL dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(uint32_t i, uint32_t j, const struct Dot2AESKey *exp_key, const struct Dot2ECPrivateKey *seed_priv, const struct Dot2ECPrivateKey *recon_priv, const struct Dot2ECPublicKey *recon_pub, const struct Dot2Cert *cert, const struct Dot2SHA256 *issuer_h, const struct Dot2ECPublicKey *issuer_pub_key, struct Dot2ECPrivateKey *priv_key);

// dot2-openssl-sign-generate.c
int INTERNAL dot2_ossl_GenerateSignature(Dot2ECPointForm form, const uint8_t *tbs, size_t tbs_size, const struct Dot2SHA256 *signer_h, EC_KEY *eck_priv_key, struct Dot2Signature *sign);
int INTERNAL dot2_ossl_GenerateXonlySignature(const struct Dot2SHA256 *h_input, EC_KEY *eck_priv_key, BIGNUM *bn_r, BIGNUM *bn_kinv, struct Dot2Signature *sign);
int INTERNAL dot2_ossl_GenerateUncompressedSignature(const struct Dot2SHA256 *input_h, EC_KEY *eck_priv_key, struct Dot2ECPoint *R_in, BIGNUM *bn_r_in, BIGNUM *bn_kinv_in, struct Dot2Signature *sign);
BIGNUM INTERNAL * dot2_ossl_GenerateSignature_s(const BIGNUM *bn_z, const BIGNUM *bn_r, const BIGNUM *bn_d, const BIGNUM *bn_kinv);
void INTERNAL dot2_ossl_CompresssSignature(struct Dot2Signature *sign);
int INTERNAL dot2_ossl_ComputeSigningParameters(struct Dot2OsslSigningParameters *params);

// dot2-openssl-sign-precompute.c
int INTERNAL dot2_ossl_InitSigningParametersComputeFunction(Dot2SigningParamsPrecomputeInterval interval);
void INTERNAL dot2_ossl_FlushSigningParametersList(struct Dot2OsslSigningParametersList *list);
void INTERNAL dot2_ossl_ReleaseSigningParametersComputeFunction(void);

// dot2-openssl-sign-verify.c
int INTERNAL dot2_ossl_VerifySignature_1(const uint8_t *tbs, size_t tbs_size, const struct Dot2SHA256 *signer_h, EC_KEY *eck_pub_key, const struct Dot2Signature *sign);
int INTERNAL dot2_ossl_VerifySignature_2(const struct Dot2SHA256 *tbs_h, const struct Dot2SHA256 *signer_h, EC_KEY *eck_pub_key, const struct Dot2Signature *sign);


#ifdef __cplusplus
}
#endif


#endif //V2X_SW_DOT2_OPENSSL_H
