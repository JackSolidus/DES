add_executable(main main.cpp ${sources} ${headers})

target_compile_features(main PUBLIC cxx_std_20)