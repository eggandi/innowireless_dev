/**
 * @file
 * @brief
 * @date 2024-06-30
 * @author user
 */

#ifndef V2X_SW_LTEV2X_HAL_API_H
#define V2X_SW_LTEV2X_HAL_API_H

#ifdef __cplusplus
extern "C" {
#endif

// 시스템 헤더 파일
#include <stdbool.h>
#include <stdint.h>

// 라이브러리 헤더파일
#include "ltev2x-hal-api-params.h"

/**
 * @brief 라이브러리 및 칩디바이스를 초기화한다.
 * @param[in] log_level 라이브러리 로그메시지 출력 레벨
 * @param[in] dev_name 모듈 통신 다바이스 또는 인터페이스 이름 (ex. /dev/spidev1.1)
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_Init(LTEV2XHALLogLevel log_level, char *dev_name);


/**
 * @brief 라이브러리 및 칩디바이스를 종료한다.
 */
void LTEV2XHAL_Close(void);

/**
 * @brief 송신 플로우를 등록한다.
 * @param[in] flow_params 등록할 송신 플로우 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_RegisterTransmitFlow(struct LTEV2XHALTxFlowParams flow_params);

/**
 * @brief 송신 플로우를 검색한다.
 * @param[in] index 검색할 송신 플로우 인덱스 (0 or 1)
 * @param[out] flow_params 반환할 저장된 송신 플로우 정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_RetrieveTransmitFlow(LTEV2XHALTxFlowIndex index, struct LTEV2XHALTxFlowParams *flow_params);

/**
 * @brief 송신 플로우를 삭제한다.
 * @param[in] index 삭제할 송신 플로우 인덱스 (0 or 1)
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_DeleteTransmitFlow(LTEV2XHALTxFlowIndex index);

/**
 * @brief MSDU를 전송한다.
 * @param[in] msdu 전송할 MSDU
 * @param[in] msdu_size 전송할 MSDU 길이
 * @param[in] tx_param 송신 파라미터
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_TransmitMSDU(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDUTxParams tx_params);

/**
 * @brief MSDU 수신을 위한 콜백함수를 등록한다
 * @param[in] ProcessMSDUCallback 콜백함수 포인터
 */
void LTEV2XHAL_RegisterCallbackProcessMSDU(void (*ProcessMSDUCallback)(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_param));

/**
 * @brief L2 ID를 확인한다.
 * @param[out] l2_id 저장할 L2 ID 포인터
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_GetL2ID(LTEV2XHALL2ID *l2_id);

/**
 * @brief L2 ID를 설정한다.
 * @param[in] l2_id 설정할 L2 ID
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_SetL2ID(LTEV2XHALL2ID l2_id);


/**
 * @brief tx profile을 등록하고 IP 통신을 활성화 한다.
 * @param[in] tx_profile 등록할 tx profile 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_RegisterTransmitProfile(struct LTEV2XHALTxProfile tx_profile);


/**
 * @brief 등록된 tx profile을 제거하고 IP 통신을 비활성화 한다.
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_DeleteTransmitProfile(void);

/**
 * @brief 디바이스에 있는 PPS 카운터를 읽어서 반환한다.
 * @retval 0: 실패
 * @retval 양수: PPS 카운터
 */
unsigned int LTEV2XHAL_GetPPSCounter(void);

/**
 * @brief IPv4 주소와 넷마스크를 획득한다.
 * @param[out] ip_addr IPv4 주소를 저장할 수 있는 포인터
 * @param[out] netmask 넷마스크를 젖아할 수 있는 포인터
 * @retval 0: 성공
 * @retval 실패(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_GetIPv4Address(uint8_t *ip_addr, uint8_t *netmask);

/**
 * @brief IPv4 주소와 netmask를 설정한다.
 * @param[in] ip_addr IPv4 주소 바이트열 (ex. {192, 168, 123, 100})
 * @param[in] netmask 서브넷마스크 바이트열 (ex. {255, 255, 255, 0})
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_SetIPv4Address(const uint8_t *ip_addr, const uint8_t *netmask);

/**
 * @brief IPv6 주소, 프리픽스 길이를 획득한다.
 * @param[out] set IPv6 주소 세트 정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_GetIPv6Address(struct LTEV2XHALIPv6AddressSet *set);

/**
 * @brief IPv6와 prefix 길이를 설정한다.
 * @param[in] ip_addr IPv6 주소 바이트열 (ex. {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff})
 * @param[in] prefix_len 프리픽스 길이
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_SetIPv6Address(const uint8_t *ip_addr, uint32_t prefix_len);

/**
 * @brief 시스템에 설정된 DNS 서버 IPv6 주소를 확인한다.
 * @param[out] primary_dns Primary DNS 서버 IPv6 주소가 저장될 버퍼
 * @param[out] secondary_dns_present Secondary DNS 서버 IPv6 주소의 존재여부가 저장될 변수 포인터
 * @param[out] secondary_dns Secondary DNS 서버 IPv6 주소가 저장될 버퍼
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_GetIPv6DNSAddress(uint8_t *primary_dns, bool *secondary_dns_present, uint8_t *secondary_dns);

/**
 * @brief DNS 서버 IPv6 주소를 설정한다.
 * @param[in] primary_dns 설정할 Primary DNS 서버 IPv6 주소
 * @param[in] secondary_dns_present Secondary DNS 서버 IPv6 주소를 설정할지 여부
 * @param[in] secondary_dns 설정할 Secondary DNS 서버 IPv6 주소
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_SetIPv6DNSAddress(const uint8_t *primary_dns, bool secondary_dns_present, const uint8_t *secondary_dns);

/**
 * @brief IPv4 Default Gateway를 획득한다.
 * @param[out] gateway_addr Gateway IPv4 주소가 저장될 4바이트 배열
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_GetIPv4GatewayAddress(uint8_t *gateway_addr);

/**
 * @brief IPv4 Default Gateway를 설정한다.
 * @param[in] gateway_addr Gateway IPv4 주소 바이트열 (ex. {192, 168, 1, 1})
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_SetIPv4GatewayAddress(const uint8_t *gateway_addr);

/**
 * @brief ltev2x-ip-0 인터페이스의 IPv6 Default Gateway를 획득한다.
 * @param[out] gateway_addr Gateway IPv6 주소가 저장될 16바이트 배열
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_GetIPv6GatewayAddress(uint8_t *gateway_addr);

/**
 * @brief IPv6 Default Gateway를 설정한다.
 * @param[in] gateway_addr Gateway IPv6 주소 바이트열
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_SetIPv6GatewayAddress(const uint8_t *gateway_addr);

/**
 * @brief 네트워크 인터페이스의 하드웨어 주소(MAC)를 획득한다.
 * @param[out] hw_addr MAC 주소가 저장될 버퍼 (6 bytes)
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_GetHWAddress(uint8_t *hw_addr);

/**
 * @brief 네트워크 인터페이스의 하드웨어 주소(MAC)를 설정한다.
 * @param[in] hw_addr 설정할 MAC 주소 바이트열 (6 bytes)
 * @retval 0: 성공
 * @retval 음수(-LTEV2XHALResultCode): 실패
 */
LTEV2XHALResultCode LTEV2XHAL_SetHWAddress(const uint8_t *hw_addr);

#ifdef __cplusplus
}
#endif


#endif //V2X_SW_LTEV2X_HAL_API_H
