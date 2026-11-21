# libpuddle-proto: the Puddle Protocol's bytes (README.md). Built on its own here, or pulled into a program with
# add_subdirectory(<protocol checkout>/lib), which gives the target `puddle_proto`.
cmake_minimum_required(VERSION 3.16)
project(puddle_proto CXX)

if(NOT TARGET OpenSSL::Crypto)
  find_package(OpenSSL 3 REQUIRED)
endif()

add_library(puddle_proto STATIC
  src/chain.cpp
  src/encoding.cpp
  src/hash.cpp
  src/json.cpp
  src/keys.cpp
  src/reqsig.cpp
  src/seal.cpp
)
target_include_directories(puddle_proto PUBLIC include)
target_compile_features(puddle_proto PRIVATE cxx_std_17)
set_target_properties(puddle_proto PROPERTIES POSITION_INDEPENDENT_CODE ON CXX_EXTENSIONS OFF)
target_link_libraries(puddle_proto PUBLIC OpenSSL::Crypto)
if(NOT MSVC)
  target_compile_options(puddle_proto PRIVATE -Wall -Wextra)
endif()

# its own test only when built on its own, so a program that pulls it in doesn't gain a test it didn't ask for
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  enable_testing()
  add_executable(proto_test tests/proto_test.cpp)
  target_compile_features(proto_test PRIVATE cxx_std_17)
  target_link_libraries(proto_test PRIVATE puddle_proto)
  add_test(NAME proto_test COMMAND proto_test ${CMAKE_CURRENT_SOURCE_DIR}/../vectors)
endif()
