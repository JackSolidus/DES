set(PSD ${PROJECT_SOURCE_DIR})

file(GLOB_RECURSE sources "${PSD}/src/*.c*")
file(GLOB_RECURSE headers "${PSD}/headers/*.h*")

include_directories("${PSD}/headers" "${PSD}/src")

add_executable(DES "${PSD}/main/main.cpp" ${sources} ${headers})

target_compile_features(DES PUBLIC cxx_std_20)

source_group(TREE ${PSD} FILES "${PSD}/main/main.cpp" ${sources} ${headers})
