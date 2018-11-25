add_library(msgbox-payload${ENTOURS_BITS} SHARED msgbox-payload.cpp msgbox-payload.def)
set_target_properties(msgbox-payload${ENTOURS_BITS} PROPERTIES PREFIX "")
set_target_properties(msgbox-payload${ENTOURS_BITS} PROPERTIES OUTPUT_NAME "msgbox-payload${ENTOURS_BITS}")
target_link_libraries(msgbox-payload${ENTOURS_BITS} ${DEPS})

add_executable(msgbox msgbox.cpp)
target_link_libraries(msgbox ${DEPS})
