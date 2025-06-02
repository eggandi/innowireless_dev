#########################################################################################################
### v2x-sw를 빌드하기 위한 CMakeLists.txt 파일
### 본 프로젝트를 제공되는 그대로(자체 변경없이) 빌드할 경우에는, "사용자 설정 영역" 항목만 수정 가능하다.
#########################################################################################################


#########################################################################################################
### 사용자 설정 영역 - 환경에 맞게 설정한다.
#########################################################################################################
## 공통 설정
set(TARGET_PLATFORM kvh1a)          # 플랫폼: x64, condor6, kvh1a, KVS-L1, hga, km2010, qulink (단위테스트 빌드 시 x64로 설정해야 함)
set(ASN1_LIB_VENDOR ffasn1c)        # ASN.1 솔루션: objasn1c, ffasn1c
set(ASN1_LIB_VERSION 764t)          # asn.1 라이브러리 버전: 764t, 760p, 744h (현재 objasn1c일 경우에만 유효)
set(V2X_SW_TARGET ltev2x-hal)       # lteaccess, ltev2x-hal
set(DEBUG_MSG_PRINT stdout)         # 디버그 메시지 출력 형태: none, stdout, syslog

## 버전
set(VERSION_MAJOR 1)    # 구조의 변화 (이전 버전과 비호환)
set(VERSION_MINOR 5)    # API 등의 변경/추가/삭제 (해당 API는 이전 버전과 비호환)
set(VERSION_PATCH 0)    # API 내부 변경 (이전 버전 API와 호환)
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

## 단위테스트 빌드
set(BUILD_UNIT_TEST false) # true, false

# dot2 라이브러리 SCMS 지원
set(SUPPORT_SCMS true) # true, false

# dot2 라이브러리 서명 생성 기능 선택 - openssl 가능
set(DOT2_SIGN_GEN openssl)

## 디바이스 보안
set(DEVICE_SECURITY false) # true, false

#########################################################################################################


#########################################################################################################
### 공통 설정
#########################################################################################################
if (${TARGET_PLATFORM} STREQUAL "condor6")
  cmake_minimum_required(VERSION 3.13)
elseif (${TARGET_PLATFORM} STREQUAL "qulink")
  cmake_minimum_required(VERSION 3.16)
else ()
  cmake_minimum_required(VERSION 3.23)
endif ()

project(v2x-sw)
set(CMAKE_C_STANDARD 99) # C 표준
set(CMAKE_CXX_STANDARD 14) # C++ 표준 (단위테스트 빌드용)
set(CMAKE_VERBOSE_MAKEFILE true) # 컴파일 메시지 출력 활성화
add_compile_options(-Wall -W -Wshadow -Wextra) # 공통 컴파일 옵션
#add_compile_options(-Wall -W -Wshadow -Wpedantic -Wextra) # 공통 컴파일 옵션
#########################################################################################################


#########################################################################################################
## 타겟플랫폼 별 설정
#########################################################################################################
# 타겟플랫폼 별로 빌드타겟, 디바이스, 인터페이스 개수 등을 설정한다.
if (${TARGET_PLATFORM} STREQUAL "x64")
  set(TARGET_BUILD x64)
  set(TARGET_OPENSSL_VER 3.0.2)
  set(TARGET_GPS_DEV f9k) # f9k (현재 OBU는 f9k만을 사용한다)
  add_compile_definitions(_X64_)
elseif (${TARGET_PLATFORM} STREQUAL "condor6")
  set(TARGET_BUILD condor6)
  set(TARGET_OPENSSL_VER 1.1.1l)
  set(TARGET_DEV_LTE_V2X SECTON)
  set(TARGET_DEV_LTE_V2X_SDK_VER secton-5.19.1-hf3-spi) # secton-5.19.1-hf3-spi | secton-5.20.0-rel-spi
  set(TARGET_DEV_DSRC saf5400)
  set(TARGET_DEV_DSRC_SDK_VER 0.15)
  set(TARGET_PLATFORM_DSRC_CHIP_DEV_NUM 2)
  set(TARGET_PLATFORM_PPS_DEV_NAME /dev/pps2)
  set(DOT2_SIGN_VERIFY openssl)
  set(TARGET_GPSD_VER 3.23.1)
  set(TARGET_GPS_DEV f9k) # f9k (현재 OBU는 f9k만을 사용한다)
  #  set(BUILD_UNIT_TEST true)
elseif (${TARGET_PLATFORM} STREQUAL "kvh1a")
  set(TARGET_BUILD kvh1a)
  set(TARGET_OPENSSL_VER 3.0.2)
  set(TARGET_DEV_LTE_V2X SECTON)
  set(TARGET_DEV_LTE_V2X_SDK_VER secton-5.20.0-rel-spi) # secton-5.19.1-hf3-spi | secton-5.20.0-rel-spi
  set(TARGET_DEV_DSRC saf5400)
  set(TARGET_DEV_DSRC_SDK_VER 0.15)
  set(TARGET_PLATFORM_DSRC_CHIP_DEV_NUM 2)
  set(TARGET_PLATFORM_PPS_DEV_NAME /dev/pps2)
  set(DOT2_SIGN_VERIFY openssl)
  set(TARGET_GPSD_VER 3.23.1)
  set(TARGET_GPS_DEV f9k) # f9k (현재 OBU는 f9k만을 사용한다)
  #  set(BUILD_UNIT_TEST true)
elseif (${TARGET_PLATFORM} STREQUAL "KVS-L1")
  set(TARGET_BUILD KVS-L1)
  set(TARGET_OPENSSL_VER 3.0.2)
  set(TARGET_DEV_LTE_V2X AG550Q)
  set(TARGET_DEV_LTE_V2X_SDK_VER L5.4.24_2.1.0_IMX8QXP_AG55xQ_SDK_02.005)
  set(TARGET_GPS_DEV f9k) # f9k (현재 OBU는 f9k만을 사용한다)
elseif (${TARGET_PLATFORM} STREQUAL "hga")
  set(TARGET_BUILD hga)
  set(TARGET_OPENSSL_VER 1.1.1f)
  set(TARGET_DEV_LTE_V2X SECTON)
  set(TARGET_DEV_LTE_V2X_SDK_VER secton-5.19.1-hf3-spi) # secton-5.19.1-hf3-spi
  set(TARGET_DEV_DSRC saf5400)
  set(TARGET_DEV_DSRC_SDK_VER 0.15)
  set(TARGET_PLATFORM_DSRC_CHIP_DEV_NUM 2)
  set(TARGET_PLATFORM_PPS_DEV_NAME /dev/pps2)
  set(DOT2_SIGN_VERIFY openssl)
  set(TARGET_GPSD_VER 3.23.1)
  set(TARGET_GPS_DEV f9p)
elseif (${TARGET_PLATFORM} STREQUAL "km2010")
  set(TARGET_BUILD km2010)
  set(TARGET_DEV_DSRC AG190W)
  set(TARGET_DEV_DSRC_SDK_VER AG190WGLR01A01V01M0G_OCPU_AG568N)
  set(TARGET_PLATFORM_DSRC_CHIP_DEV_NUM 2)
elseif (${TARGET_PLATFORM} STREQUAL "qulink")
  set(TARGET_BUILD qulink)
  set(TARGET_OPENSSL_VER 3.0.2) # 3.0.9
  set(TARGET_DEV_LTE_V2X SA525M)
  set(TARGET_DEV_LTE_V2X_SDK_VER snaptel-sdk-telsdk.lnx.2.0.c22)
  set(TARGET_DEV_DSRC saf5400)
  set(TARGET_DEV_DSRC_SDK_VER 0.15)
  set(TARGET_PLATFORM_DSRC_CHIP_DEV_NUM 2)
  set(TARGET_PLATFORM_PPS_DEV_NAME /dev/pps0)
  set(DOT2_SIGN_VERIFY openssl)
  set(TARGET_GPSD_VER 3.23.1) # gpsd 없음
  set(TARGET_GPS_DEV f9k) # f9k (현재 OBU는 f9k만을 사용한다)
else ()
  message(FATAL_ERROR "Not supported target platform - ${TARGET_PLATFORM}")
endif ()
#########################################################################################################


#########################################################################################################
# 기타 설정
#########################################################################################################
# 프로젝트 루트 디렉터리 (v2x-sw)
set(PROJECT_ROOT ${CMAKE_CURRENT_LIST_DIR})
# 버전 플래그
add_compile_definitions(_VERSION_="${VERSION}")
# 디버그 메시지 출력 형태
if (${DEBUG_MSG_PRINT} STREQUAL "stdout")
  add_compile_definitions(_DEBUG_STDOUT_)
elseif (${DEBUG_MSG_PRINT} STREQUAL "syslog")
  add_compile_definitions(_DEBUG_SYSLOG_)
endif ()
# objasn1c 버전 번호
if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
  if (${ASN1_LIB_VERSION} STREQUAL "744h")
    add_compile_definitions(_OBJASN1C_VERSION_744H_)
  elseif (${ASN1_LIB_VERSION} STREQUAL "760p")
    add_compile_definitions(_OBJASN1C_VERSION_760P_)
  elseif (${ASN1_LIB_VERSION} STREQUAL "764t")
    add_compile_definitions(_OBJASN1C_VERSION_764T_)
  endif ()
else ()
  set(ASN1_LIB_VERSION "")
endif ()
# 접속계층 라이브러리
if (${V2X_SW_TARGET} STREQUAL "ltev2x-hal")
  add_compile_definitions(_LTEV2X_HAL_)
elseif (${V2X_SW_TARGET} STREQUAL "lteaccess")
  add_compile_definitions(_LTEACCESS_)
else ()
  message(FATAL_ERROR "Not supported v2x-sw target - ${V2X_SW_TARGET}")
endif ()
#########################################################################################################


#########################################################################################################
# 각 프로젝트 빌드
#########################################################################################################
# 단위테스트 빌드 설정
if (BUILD_UNIT_TEST)
  message("[${TARGET_PLATFORM}][unit-test] BUILD")
  set(TARGET_BUILD kvh1a)
  set(GTEST_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/test/google-test/)
else ()
  message("[${TARGET_PLATFORM}][unit-test] NOT BUILD")
endif ()

# 디바이스 보안 설정
if (DEVICE_SECURITY)
  add_compile_definitions(_DEVICE_SECURITY_)
endif ()

## 라이브러리 빌드
add_subdirectory(src/libs/dot2-2016)
add_subdirectory(src/libs/dot3-2016)
add_subdirectory(src/libs/j29451)
# add_subdirectory(src/libs/wlanaccess)
# add_subdirectory(src/libs/ltev2x-hal)
# add_subdirectory(src/libs/cvcoctci-2023)

### 유틸리티 빌드
# add_subdirectory(src/apps/utils/ltev2x/ip-ltev2x)
# add_subdirectory(src/apps/utils/ltev2x/sdee-ltev2x)
# add_subdirectory(src/apps/utils/ltev2x/wsm-ltev2x)
# add_subdirectory(src/apps/utils/ltev2x/wsm-test-ltev2x)

# add_subdirectory(src/apps/utils/dsrc/addr-dsrc)
# add_subdirectory(src/apps/utils/dsrc/chan-dsrc)
# add_subdirectory(src/apps/utils/dsrc/init-dsrc)
# add_subdirectory(src/apps/utils/dsrc/sdee-dsrc)
# add_subdirectory(src/apps/utils/dsrc/wsm-dsrc)

# add_subdirectory(src/apps/utils/common/tcia-2023)
# add_subdirectory(src/apps/utils/common/app-cert-req)
# add_subdirectory(src/apps/utils/common/bootstrap)
# add_subdirectory(src/apps/utils/common/bsmd)
# add_subdirectory(src/apps/utils/common/cmhf)
# add_subdirectory(src/apps/utils/common/crl-req)
# add_subdirectory(src/apps/utils/common/id-cert-req)
# add_subdirectory(src/apps/utils/common/pseudonym-cert-req)
# add_subdirectory(src/apps/utils/common/sec-tester)
#add_subdirectory(src/apps/utils/common/secton-aes)

### 샘플 어플리케이션 빌드

#########################################################################################################
