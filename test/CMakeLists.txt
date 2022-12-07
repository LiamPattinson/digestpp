enable_testing()

# Get google test suit
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
)
FetchContent_MakeAvailable(googletest)

add_executable(digestpp-tests ./test.cc ./test_vectors.cc)
target_link_libraries(digestpp-tests PRIVATE digestpp::digestpp)
target_link_libraries(digestpp-tests PRIVATE gtest gtest_main)

include(GoogleTest)
gtest_discover_tests(digestpp-tests)

add_custom_target(build-tests)
add_dependencies(build-tests digestpp-tests)

add_custom_target(
    run-tests
    COMMAND digestpp-tests 
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/test
)
add_dependencies(run-tests build-tests)

add_custom_target(tests)
add_dependencies(tests run-tests)
