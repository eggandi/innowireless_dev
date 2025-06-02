
## tcia-2023 어플리케이션을 빌드하기 위한 CMakeLists.txt 파일


#
# 빌드 출력 설정
#
set(TARGET_APP_LTE_V2X tcia-2023)

set(DOT2_SIGN_VERIFY openssl)
set(BUILD_TARGET_APP_LTE_V2X true)

#
# dot2라이브러리의 서명검증 기능이 openssl이 아니면 tcia3-lte-v2x를 빌드하지 않는다.
#
if (${DOT2_SIGN_VERIFY} STREQUAL "openssl")
  set(BUILD_TARGET_APP_LTE_V2X true)
else ()
  set(BUILD_TARGET_APP_LTE_V2X false)
endif ()

#
# x64 플랫폼용으로 빌드 시와 단위테스트 빌드 시에는 본 유틸리티를 빌드하지 않는다.
#  - 본 유틸리티는 실제 통신플랫폼에서만 사용된다.
#
if (${TARGET_PLATFORM} STREQUAL "x64" OR BUILD_UNIT_TEST)
  message("[${TARGET_PLATFORM}][${TARGET_APP_LTE_V2X}] NOT BUILD")
  return()
endif ()

#
# 유틸리티 빌드
if (BUILD_TARGET_APP_LTE_V2X)
  message("[${TARGET_PLATFORM}][${TARGET_APP_LTE_V2X}] BUILD")
  add_executable(${TARGET_APP_LTE_V2X})
  target_compile_definitions(${TARGET_APP_LTE_V2X} PRIVATE _TCIA2023_LTE_V2X_)
  target_include_directories(${TARGET_APP_LTE_V2X} PRIVATE ${PROJECT_ROOT}/src/apps/depend/include)
  target_include_directories(${TARGET_APP_LTE_V2X} PRIVATE src src/include)
  target_link_directories(${TARGET_APP_LTE_V2X} PRIVATE ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  target_link_directories(${TARGET_APP_LTE_V2X} PRIVATE ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD}/lte)
  target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE pthread rt m gps)
  target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE j29451)
  target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE cvcoctci-2023)

  if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE objasn1-tci-2021 objasn1-dot2-2021 objasn1-dot3-2016 objasn1-j2735-2016 asn1per asn1oer asn1rt)
  elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE ffasn1-tci-2023 ffasn1-dot2-2021 ffasn1-dot3-2016 ffasn1-j2735-2016 ffasn1-base)
  else ()
    message(FATAL_ERROR "Not supported asn.1 library - ${ASN1_LIB_VENDOR}")
  endif ()

  if (${V2X_SW_TARGET} STREQUAL "lteaccess")
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE dot3)
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE dot2 zip)
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE lteaccess)
  elseif (${V2X_SW_TARGET} STREQUAL "ltev2x-hal")
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE dot3-2016)
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE dot2-2016 zip)
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE ltev2x-hal)
  else ()
    message(FATAL_ERROR "Not supported v2x-sw target - ${V2X_SW_TARGET}")
  endif ()

  target_link_options(${TARGET_APP_LTE_V2X} PRIVATE -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--allow-shlib-undefined)
  target_sources(${TARGET_APP_LTE_V2X} PRIVATE
          src/ipv6/tcia2023-ipv6-addr.c
          src/ipv6/tcia2023-ipv6-icmp.c
          src/ipv6/tcia2023-ipv6-rx.c
          src/ipv6/tcia2023-ipv6-tx.c
          src/lte-v2x/tcia2023-lte-v2x.c
          src/ts-if/tcia2023-ts-if.c
          src/ts-if/tcia2023-ts-if-indication.c
          src/ts-if/tcia2023-ts-if-process-tci.c
          src/ts-if/tcia2023-ts-if-process-tci16093dsrc.c
          src/ts-if/tcia2023-ts-if-process-tci16093pc5.c
          src/ts-if/tcia2023-ts-if-process-tci16094.c
          src/ts-if/tcia2023-ts-if-process-tci29451.c
          src/ts-if/tcia2023-ts-if-process-tci31611.c
          src/ts-if/tcia2023-ts-if-process-tci80211.c
          src/ts-if/tcia2023-ts-if-process-tcisutctrl.c
          src/ts-if/tcia2023-ts-if-response.c
          src/tcia2023.c
          src/tcia2023-bsm.c
          src/tcia2023-dut-state.c
          src/tcia2023-input-params.c
          src/tcia2023-interface.c
          src/tcia2023-log.c
          src/tcia2023-security.c
          src/tcia2023-wra.c
          src/tcia2023-wsa.c
          src/tcia2023-wsm.c)
else ()
  message("[${TARGET_PLATFORM}][${TARGET_APP_LTE_V2X}] NOT BUILD")
endif ()

#
# 빌드 결과물을 output 디렉토리로 복사
#
set(OUTPUT_DIR ${PROJECT_ROOT}/src/apps/output/${TARGET_BUILD})
if (BUILD_TARGET_APP_LTE_V2X)
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X}-${VERSION})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${TARGET_APP_LTE_V2X} ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${TARGET_APP_LTE_V2X} ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X}-${VERSION})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${CMAKE_CURRENT_LIST_DIR}/${TARGET_APP_LTE_V2X})
endif ()