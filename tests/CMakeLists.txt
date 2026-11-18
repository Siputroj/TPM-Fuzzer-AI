find_package(Catch2 3 REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(FUZZER_TESTS
  parser/byte_parser_test.cc
  harness/tpm_wrapper_test.cc
  harness/session_auth_test.cc
  ${CMAKE_SOURCE_DIR}/src/parser/byte_parser.cc
  ${CMAKE_SOURCE_DIR}/src/harness/tpm_wrapper.c
  ${CMAKE_SOURCE_DIR}/src/harness/session_auth.cc
  ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/tpm/src/support/CommandCodeAttributes.c
)

target_link_libraries(FUZZER_TESTS
  PRIVATE
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

target_include_directories(FUZZER_TESTS
  PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/parser
    ${CMAKE_SOURCE_DIR}/include/harness
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/tpm/include
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/tpm/include/private
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/tpm/include/private/prototypes
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/tpm/cryptolibs/common/include
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/tpm/cryptolibs/TpmBigNum/include
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/tpm/cryptolibs/Ossl/include
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/Platform/include
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/TpmConfiguration
    ${CMAKE_SOURCE_DIR}/vendor/TPM/TPMCmd/TpmConfiguration/TpmConfiguration
)

target_compile_definitions(FUZZER_TESTS PRIVATE
  SYM_LIB=Ossl
  HASH_LIB=Ossl
  MATH_LIB=TpmBigNum
  BN_MATH_LIB=Ossl
)

# Disable fuzz sanitizer for tests
target_compile_options(FUZZER_TESTS PRIVATE
  -fno-sanitize=fuzzer
)

target_link_options(FUZZER_TESTS PRIVATE
  -fno-sanitize=fuzzer
)

include(Catch)
catch_discover_tests(FUZZER_TESTS)
