# Option to use ml-kem C++20 library instead of liboqs
# Set via: idf.py -DUSE_ML_KEM_LIBRARY=ON build
option(USE_ML_KEM_LIBRARY "Use ml-kem C++20 library instead of liboqs" OFF)

if(USE_ML_KEM_LIBRARY)
    # Use ml-kem C++20 library implementation
    get_filename_component(ML_KEM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../impl/ml-kem" ABSOLUTE)
    
    idf_component_register(SRCS "performance.c" "mlkem768_mlkem.cpp"
                        INCLUDE_DIRS "."
                        PRIV_INCLUDE_DIRS "${ML_KEM_ROOT}/include"
                                        "${ML_KEM_ROOT}/sha3/include"
                                        "${ML_KEM_ROOT}/subtle/include"
                                        "${ML_KEM_ROOT}/RandomShake/include"
                        PRIV_REQUIRES esp_timer)
    
    # Set C++ standard to C++20 for the wrapper
    target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_20)
    # Apply C++-specific flags only to C++ files
    target_compile_options(${COMPONENT_LIB} PRIVATE 
        $<$<COMPILE_LANGUAGE:CXX>:-std=gnu++20>
        $<$<COMPILE_LANGUAGE:CXX>:-fconstexpr-depth=1000>
        $<$<COMPILE_LANGUAGE:CXX>:-fconstexpr-ops-limit=10000000>
        $<$<COMPILE_LANGUAGE:CXX>:-fpermissive>
        $<$<COMPILE_LANGUAGE:CXX>:-Wno-error=shift-count-overflow>
    )
    
    # Add preprocessor definition
    target_compile_definitions(${COMPONENT_LIB} PRIVATE USE_ML_KEM_LIBRARY)
else()
    # Use original liboqs-based implementation
    idf_component_register(SRCS "performance.c"
                        INCLUDE_DIRS "." PRIV_REQUIRES liboqs_mlkem esp_timer)
endif()
