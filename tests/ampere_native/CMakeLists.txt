cmake_minimum_required(VERSION 3.24)
project(AmpereNativeTests LANGUAGES C CXX)
# CPU-only tests for the experimental Ampere policy and bundle logic. No GPU, no NVIDIA inputs.
enable_testing()
add_executable(ampere_policy_tests policy_tests.cpp ../../source/native/ampere_policy.cpp)
target_compile_features(ampere_policy_tests PRIVATE cxx_std_20)
target_compile_definitions(ampere_policy_tests PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
add_test(NAME ampere_policy COMMAND ampere_policy_tests)

add_executable(ampere_bundle_tests bundle_tests.cpp ../../source/native/ampere_bundle.cpp)
target_compile_features(ampere_bundle_tests PRIVATE cxx_std_20)
target_compile_definitions(ampere_bundle_tests PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(ampere_bundle_tests PRIVATE bcrypt)
add_test(NAME ampere_bundle COMMAND ampere_bundle_tests)

add_executable(ampere_publication_tests publication_tests.cpp ../../source/native/ampere_bundle.cpp)
target_compile_features(ampere_publication_tests PRIVATE cxx_std_20)
target_compile_definitions(ampere_publication_tests PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
add_test(NAME ampere_publication COMMAND ampere_publication_tests)

add_executable(ampere_pacing_tests pacing_tests.cpp ../../source/native/flip_metering.cpp)
target_compile_features(ampere_pacing_tests PRIVATE cxx_std_20)
target_compile_definitions(ampere_pacing_tests PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
add_test(NAME ampere_pacing COMMAND ampere_pacing_tests)

# Unsupported multipliers must refuse before hardware queries or publication.
add_executable(ampere_experiment_tests experiment_tests.cpp
    ../../source/native/ampere_experiment.cpp
    ../../source/native/ampere_bundle.cpp
    ../../source/native/ampere_policy.cpp
    ../../source/native/dlssg_provider_policy.cpp
    ../../source/native/third_party/minhook/src/buffer.c
    ../../source/native/third_party/minhook/src/hook.c
    ../../source/native/third_party/minhook/src/trampoline.c
    ../../source/native/third_party/minhook/src/hde/hde64.c)
target_include_directories(ampere_experiment_tests PRIVATE ../../source/native/third_party/minhook/include)
target_compile_features(ampere_experiment_tests PRIVATE cxx_std_20)
target_compile_definitions(ampere_experiment_tests PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(ampere_experiment_tests PRIVATE bcrypt dxgi version)
add_test(NAME ampere_experiment COMMAND ampere_experiment_tests)
