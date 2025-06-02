
## bsmd 유틸리티를 빌드하기 위한 CMakeLists.txt 파일


#
# 빌드 사용자 설정
#
set(SUPPORT_POWER_OFF_DETECT false) # true, false (Power off 감지 기능 지원 여부). Condor6의 경우 true
set(SUPPORT_USER_POWER_OFF false) # 사용자 입력에 의한 전원 off 기능 지원

#
# 빌드 출력 설정
#
set(TARGET_APP_DSRC bsmd-dsrc)
set(TARGET_APP_LTE_V2X bsmd-ltev2x)


#
# x64 플랫폼용으로 빌드 시와 단위테스트 빌드 시에는 본 유틸리티를 빌드하지 않는다.
#  - 본 유틸리티는 실제 통신플랫폼에서만 사용된다.
#
if (${TARGET_PLATFORM} STREQUAL "x64" OR BUILD_UNIT_TEST)
  message("[${TARGET_PLATFORM}][${TARGET_APP_DSRC}] NOT BUILD")
  message("[${TARGET_PLATFORM}][${TARGET_APP_LTE_V2X}] NOT BUILD")
  return()
endif ()


#
# 유틸리티 빌드
#
# bsmd-dsrc
message("[${TARGET_PLATFORM}][${TARGET_APP_DSRC}] BUILD")
add_executable(${TARGET_APP_DSRC})
target_compile_definitions(${TARGET_APP_DSRC} PRIVATE _BSMD_DSRC_)
target_include_directories(${TARGET_APP_DSRC} PRIVATE ${PROJECT_ROOT}/src/apps/depend/include)
target_include_directories(${TARGET_APP_DSRC} PRIVATE src src/include)
target_link_directories(${TARGET_APP_DSRC} PRIVATE ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
target_link_libraries(${TARGET_APP_DSRC} PRIVATE pthread rt m gps)
target_link_libraries(${TARGET_APP_DSRC} PRIVATE dot3-2016)
target_link_libraries(${TARGET_APP_DSRC} PRIVATE dot2-2016)
if (SUPPORT_SCMS)
  target_link_libraries(${TARGET_APP_DSRC} PRIVATE curl zip)
endif ()
target_link_libraries(${TARGET_APP_DSRC} PRIVATE j29451)
if (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
  target_link_libraries(${TARGET_APP_DSRC} PRIVATE ffasn1-dot2-2021 ffasn1-dot3-2016 ffasn1-j2735-2016 ffasn1-base)
elseif (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
  target_link_libraries(${TARGET_APP_DSRC} PRIVATE objasn1-dot2-2021 objasn1-dot3-2016 objasn1-j2735-2016 asn1per asn1oer asn1rt)
endif ()
target_link_options(${TARGET_APP_DSRC} PRIVATE -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--allow-shlib-undefined)
target_sources(${TARGET_APP_DSRC} PRIVATE
        src/bsmd-input-params.c
        src/bsmd.c
        src/bsmd-bsm.c
        src/dsrc/bsmd-dsrc.c
        src/bsmd-log.c
        src/bsmd-poweroff.c
        src/bsmd-security.c)
if (${TARGET_DEV_DSRC} STREQUAL "saf5100" OR ${TARGET_DEV_DSRC} STREQUAL "saf5400")
  target_link_libraries(${TARGET_APP_DSRC} PRIVATE wlanaccess LLC)
elseif (${TARGET_DEV_DSRC} STREQUAL "craton2")
  target_link_libraries(${TARGET_APP_DSRC} PRIVATE wlanaccess atlklocal_linux_u tomcrypt tommath m)
endif ()

# Power off 감지 기능 지원 여부
if (SUPPORT_POWER_OFF_DETECT)
  target_compile_definitions(${TARGET_APP_DSRC} PRIVATE _SUPPORT_POWER_OFF_DETECT_)
endif ()

# 사용자 입력 기반 Power off 기능 지원 여부
if (SUPPORT_USER_POWER_OFF)
  target_compile_definitions(${TARGET_APP_DSRC} PRIVATE _SUPPORT_USER_POWER_OFF_)
endif ()

# bsmd-lte-v2x
if (NOT ${TARGET_PLATFORM} STREQUAL "x64")
  message("[${TARGET_PLATFORM}][${TARGET_APP_LTE_V2X}] BUILD")
  add_executable(${TARGET_APP_LTE_V2X})
  target_compile_definitions(${TARGET_APP_LTE_V2X} PRIVATE _BSMD_LTE_V2X_)
  target_include_directories(${TARGET_APP_LTE_V2X} PRIVATE ${PROJECT_ROOT}/src/apps/depend/include)
  target_include_directories(${TARGET_APP_LTE_V2X} PRIVATE src src/include)
  target_link_directories(${TARGET_APP_LTE_V2X} PRIVATE ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE pthread rt m gps)
  target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE dot3-2016)
  target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE dot2-2016)
  if (SUPPORT_SCMS)
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE curl zip)
  endif ()
  target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE j29451)
  if (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE ffasn1-dot2-2021 ffasn1-dot3-2016 ffasn1-j2735-2016 ffasn1-base)
  elseif (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE objasn1-dot2-2021 objasn1-dot3-2016 objasn1-j2735-2016 asn1per asn1oer asn1rt)
  endif ()
  if (${TARGET_DEV_LTE_V2X} STREQUAL "SECTON")
    target_link_libraries(${TARGET_APP_LTE_V2X} PRIVATE ltev2x-hal atlkremote_linux_u atlkcv2x atlkcli atlkpoti atlksmx atlktest)
  endif ()
  target_link_options(${TARGET_APP_LTE_V2X} PRIVATE -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--allow-shlib-undefined)
  target_sources(${TARGET_APP_LTE_V2X} PRIVATE
          src/lte-v2x/bsmd-lte-v2x.c
          src/bsmd.c
          src/bsmd-bsm.c
          src/bsmd-input-params.c
          src/bsmd-log.c
          src/bsmd-poweroff.c
          src/bsmd-security.c)
  # Power off 감지 기능 지원 여부
  if (SUPPORT_POWER_OFF_DETECT)
    target_compile_definitions(${TARGET_APP_LTE_V2X} PRIVATE _SUPPORT_POWER_OFF_DETECT_)
  endif ()

  # 사용자 입력 기반 Power off 기능 지원 여부
  if (SUPPORT_USER_POWER_OFF)
    target_compile_definitions(${TARGET_APP_LTE_V2X} PRIVATE _SUPPORT_USER_POWER_OFF_)
  endif ()
else ()
  message("[${TARGET_PLATFORM}][${TARGET_APP_LTE_V2X}] NOT BUILD")
endif ()


#
# 빌드 결과물을 output 디렉토리로 복사
#
set(OUTPUT_DIR ${PROJECT_ROOT}/src/apps/output/${TARGET_BUILD})
# bsmd-dsrc
add_custom_command(TARGET ${TARGET_APP_DSRC} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        remove ${OUTPUT_DIR}/${TARGET_APP_DSRC})
add_custom_command(TARGET ${TARGET_APP_DSRC} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        remove ${OUTPUT_DIR}/${TARGET_APP_DSRC}-${VERSION})
add_custom_command(TARGET ${TARGET_APP_DSRC} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        copy ${TARGET_APP_DSRC} ${OUTPUT_DIR}/${TARGET_APP_DSRC})
add_custom_command(TARGET ${TARGET_APP_DSRC} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        copy ${TARGET_APP_DSRC} ${OUTPUT_DIR}/${TARGET_APP_DSRC}-${VERSION})
add_custom_command(TARGET ${TARGET_APP_DSRC} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
        remove ${TARGET_APP_DSRC})
# bsmd-lte-v2x
if (${DOT2_SIGN_VERIFY} STREQUAL "openssl")
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X}-${VERSION})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${TARGET_APP_LTE_V2X} ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${TARGET_APP_LTE_V2X} ${OUTPUT_DIR}/${TARGET_APP_LTE_V2X}-${VERSION})
  add_custom_command(TARGET ${TARGET_APP_LTE_V2X} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${TARGET_APP_LTE_V2X})
endif ()
