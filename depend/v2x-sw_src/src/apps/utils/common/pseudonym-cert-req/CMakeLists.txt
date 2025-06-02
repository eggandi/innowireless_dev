
## pseudonym-cert-req 유틸리티를 빌드하기 위한 CMakeLists.txt


#
# 빌드 출력 설정
#
set(TARGET_APP pseudonym-cert-req)


#
# 단위테스트 빌드 시에는 본 유틸리티를 빌드하지 않는다.
#
if (BUILD_UNIT_TEST)
  message("[${TARGET_PLATFORM}][${TARGET_APP}] NOT BUILD")
  return()
else ()
  message("[${TARGET_PLATFORM}][${TARGET_APP}] BUILD")
endif ()


#
# 유틸리티 빌드
#
add_executable(${TARGET_APP})
target_include_directories(${TARGET_APP} PRIVATE ${PROJECT_ROOT}/src/apps/depend/include)
target_include_directories(${TARGET_APP} PRIVATE src)
target_link_directories(${TARGET_APP} PRIVATE ${PROJECT_ROOT}/src/apps/depend/lib/${TARGET_BUILD})
target_link_libraries(${TARGET_APP} PRIVATE dot2-2016)
if (SUPPORT_SCMS)
  target_link_libraries(${TARGET_APP} PRIVATE curl zip)
endif ()
if (${ASN1_LIB_VENDOR} STREQUAL "objasn1c")
  target_link_libraries(${TARGET_APP} PRIVATE objasn1-dot2-2021 asn1per asn1oer asn1rt)
elseif (${ASN1_LIB_VENDOR} STREQUAL "ffasn1c")
  target_link_libraries(${TARGET_APP} PRIVATE ffasn1-dot2-2021 ffasn1-base)
else ()
  message(FATAL_ERROR "Not supported asn.1 library - ${ASN1_LIB_VENDOR}")
endif ()
target_link_options(${TARGET_APP} PRIVATE -Wl,--hash-style=gnu -Wl,--as-needed -Wl,--allow-shlib-undefined)
target_sources(${TARGET_APP} PRIVATE
        src/pseudonym-cert-req.c
        src/pseudonym-cert-req-cert.c
        src/pseudonym-cert-req-download.c
        src/pseudonym-cert-req-download-info.c
        src/pseudonym-cert-req-file.c
        src/pseudonym-cert-req-input-params.c
        src/pseudonym-cert-req-provisioning.c)
if (${DOT2_SIGN_VERIFY} STREQUAL "saf5400")
  target_link_libraries(${TARGET_APP} PRIVATE LLC)
elseif (${DOT2_SIGN_VERIFY} STREQUAL "craton2")
  target_link_libraries(${TARGET_APP} PRIVATE atlklocal_linux_u tomcrypt tommath m rt)
endif ()


#
# 빌드 결과물을 output 디렉토리로 복사
#
set(OUTPUT_DIR ${PROJECT_ROOT}/src/apps/output/${TARGET_BUILD})
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
