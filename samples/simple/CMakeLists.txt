add_library(simple${ENTOURS_BITS} SHARED simple.cpp simple.def)
set_target_properties(simple${ENTOURS_BITS} PROPERTIES PREFIX "")
set_target_properties(simple${ENTOURS_BITS} PROPERTIES OUTPUT_NAME "simple${ENTOURS_BITS}")
target_link_libraries(simple${ENTOURS_BITS} ${DEPS})

add_executable(sleep5 sleep5.cpp)
target_link_libraries(sleep5 ${DEPS})
