set(CMSAN_TEST_DEPS ${SANITIZER_COMMON_LIT_TEST_DEPS})
set(CMSAN_TESTSUITES)

# No unit tests ATM

add_lit_testsuite(check-cmsan "Running the CMSan tests"
  ${INTERCEPTION_TESTSUITES}
  DEPENDS ${INTERCEPTION_TEST_DEPS})
set_target_properties(check-cmsan PROPERTIES FOLDER "Compiler-RT Misc")
