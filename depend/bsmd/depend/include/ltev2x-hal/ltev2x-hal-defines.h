/**
 * @file
 * @brief
 * @date 2024-06-30
 * @author user
 */

#ifndef V2X_SW_LTEV2X_HAL_DEFINES_H
#define V2X_SW_LTEV2X_HAL_DEFINES_H

#ifndef MAC_ALEN
#define MAC_ALEN (6) ///< MAC 주소 길이 (바이트 단위)
#endif

#ifndef MAC_ADDR_STR_MAX_LEN
#define MAC_ADDR_STR_MAX_LEN ((MAC_ALEN*2)+5) ///< MAC 주소 문자열 최대 길이 (바이트 단위)
#endif

#ifndef IPv4_ALEN
#define IPv4_ALEN (4) ///< IPv4 주소 길이 (바이트 단위)
#endif

#ifndef IPv4_ADDR_STR_MAX_LEN
#define IPv4_ADDR_STR_MAX_LEN ((IPv4_ALEN*2)+3) ///< IPv6 주소 문자열 최대 길이 (바이트 단위)
#endif

#ifndef IPv6_ALEN
#define IPv6_ALEN (16) ///< IPv6 주소 길이 (바이트 단위)
#endif

#ifndef IPv6_ADDR_STR_MAX_LEN
#define IPv6_ADDR_STR_MAX_LEN ((IPv6_ALEN*2)+7) ///< IPv6 주소 문자열 최대 길이 (바이트 단위)
#endif

#endif //V2X_SW_LTEV2X_HAL_DEFINES_H
