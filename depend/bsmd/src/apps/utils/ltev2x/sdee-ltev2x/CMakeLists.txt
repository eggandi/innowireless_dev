
## sdee-lte-v2x 유틸리티를 빌드하기 위한 CMakeLists.txt 파일


#
# 빌드 출력 설정
#
set(TARGET_APP sdee-ltev2x)


#
# 단위테스트 빌드 시에는 본 유틸리티를 빌드하지 않는다.
#  - 본 유틸리티는 주로 실제 통신플랫폼에서 사용되며, 루프백 테스트에 한해서는 x64 플랫폼에서도 사용할 수 있다.

# dot2 라이브러리의 서명검증기능이 openssl 기반이 아니면 본 유틸리티를 빌드하지 않는다.
#
if (BUILD_UNIT_TEST OR NOT ${DOT2_SIGN_VERIFY} STREQUAL "openssl")
  message("[${TARGET_PLATFORM}][${TARGET_APP}] NOT BUILD")
  return()
endif ()


if (${TARGET_PLATFORM} STREQUAL "kvh1a")
  message("[${TARGET_PLATFORM}][${TARGET_APP}] BUILD")
  # 빌드
  add_executable(${TARGET_APP})
  target_include_directories(${TARGET_APP} PRIVATE ${PROJECT_ROOT}/src/apps/depend/include)
  target_include_directories(${TARGET_APP} PRIVATE src)
  target_link_directories(${TARGET_APP} PRIVATE ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
  target_link_libraries(${TARGET_APP} PRIVATE gps pthread rt)
  target_link_libraries(${TARGET_APP} PRIVATE dot3-2016)
  if (SUPPORT_SCMS)
    target_link_libraries(${TARGET_APP} PRIVATE curl zip)
  endif()
  target_link_libraries(${TARGET_APP} PRIVATE dot2-2016)
  target_link_libraries(${TARGET_APP} PRIVATE ltev2x-hal atlkremote_linux_u atlkcv2x atlkcli atlkpoti atlksmx atlktest)

  if (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
    target_link_libraries(${TARGET_APP} PRIVATE ffasn1-dot3-2016 ffasn1-dot2-2021 ffasn1-base)
  elseif (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
    target_link_libraries(${TARGET_APP} PRIVATE objasn1-dot3-2016 asn1per asn1oer asn1rt)
  endif ()
  target_link_options(${TARGET_APP} PRIVATE -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--allow-shlib-undefined)
  target_sources(${TARGET_APP} PRIVATE
          src/sdee-ltev2x.c
          src/sdee-ltev2x-crypto-material.c
          src/sdee-ltev2x-input-params.c
          src/sdee-ltev2x-rx.c
          src/sdee-ltev2x-tx.c)

  #
  # 빌드 결과물을 output 디렉토리로 복사
  #
  set (OUTPUT_DIR ${PROJECT_ROOT}/src/apps/output/${TARGET_BUILD})
  add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${OUTPUT_DIR}/${TARGET_APP})
  add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${OUTPUT_DIR}/${TARGET_APP}-${VERSION})
  add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${TARGET_APP} ${OUTPUT_DIR}/${TARGET_APP})
  add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          copy ${TARGET_APP} ${OUTPUT_DIR}/${TARGET_APP}-${VERSION})
  add_custom_command(TARGET ${TARGET_APP} POST_BUILD COMMAND ${CMAKE_COMMAND} -E
          remove ${TARGET_APP})
else ()
  message("[${TARGET_PLATFORM}][${TARGET_APP}] NOT BUILD")
endif ()