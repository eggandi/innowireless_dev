/** 
 * @file
 * @brief 라이브러리 내부에서 사용되는 각종 유형을 정의한 파일
 * @date 2020-03-10
 * @author gyun
 */


#ifndef V2X_SW_DOT2_INTERNAL_TYPES_H
#define V2X_SW_DOT2_INTERNAL_TYPES_H


// 시스템 헤더 파일
#include <stdint.h>

// 라이브러리 의존 헤더 파일
#include "openssl/ec.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"


/**
 * @brief 서명 정보
 */
struct Dot2Signature
{
  struct Dot2ECPoint R_r; ///< 서명 R 또는 r
  uint8_t s[DOT2_EC_256_KEY_LEN]; ///< 서명 s
};


/**
 * @brief 원형 영역정보
 */
struct Dot2CircularRegion
{
  struct Dot2TwoDLocation center; ///< 중심점 좌표
  uint16_t radius; ///< 반지름(미터단위)
};


/**
 * @brief End-entity 인증서 내 포함된 권한정보(들)
 *
 * IEEE 1609.2-2016 표준에는 PsidSsp 유형의 권한으로 정의되어 있으나,
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라 실제로는 SSP 정보는 사용되지 않고 있다.
 */
struct Dot2EECertPermissions
{
  Dot2CertPermissionNum psid_num; ///< PSID 권한 개수
  Dot2PSID psid[kDot2CertPermissionNum_Max]; ///< PSID 권한(들)
};


/**
 * @brief 키쌍 바이트열 정보
 */
struct Dot2ECKeyPairOcts
{
  struct Dot2ECPrivateKey priv_key; ///< 개인키
  struct Dot2ECPublicKey pub_key; ///< 공개키(x, y)
};


/**
 * @brief 키쌍 바이트열 및 EC_KEY 정보
 */
struct Dot2ECKeyPair
{
  struct Dot2ECKeyPairOcts octs; ///< 개인키/공개키 바이트열
  EC_KEY *eck; ///< 개인키/공개키가 포함된 EC_KEY 정보
};


/*
 * @brief AES 암호화 TAG 바이트열
 */
struct Dot2AESTag
{
  uint8_t octs[DOT2_AES_128_TAG_LEN]; ///< 바이트열
} __attribute__((packed));


/*
 * @brief AES 암호화 Nonce 바이트열
 */
struct Dot2AESNonce
{
  uint8_t octs[DOT2_AES_128_NONCE_LEN]; ///< 바이트열
} __attribute__((packed));


/*
 * @brief AES 암호화 Authentication Tag 바이트열
 */
struct Dot2AESAuthTag
{
  uint8_t octs[DOT2_AUTH_TAG_LEN]; ///< 바이트열
} __attribute__((packed));


#endif //V2X_SW_DOT2_INTERNAL_TYPES_H
