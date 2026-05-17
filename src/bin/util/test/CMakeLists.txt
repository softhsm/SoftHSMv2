project(softhsm2utiltest)

add_test(
	NAME ${PROJECT_NAME}-ml-dsa
	COMMAND ${CMAKE_COMMAND} -E env
			top_builddir=${CMAKE_BINARY_DIR}
			top_srcdir=${CMAKE_SOURCE_DIR}
			srcdir=${CMAKE_CURRENT_SOURCE_DIR}
			builddir=${CMAKE_CURRENT_BINARY_DIR}
			bash ${CMAKE_CURRENT_SOURCE_DIR}/mldsa44-import-key-test.sh
)

add_test(
		NAME ${PROJECT_NAME}-ml-kem
		COMMAND ${CMAKE_COMMAND} -E env
		top_builddir=${CMAKE_BINARY_DIR}
		top_srcdir=${CMAKE_SOURCE_DIR}
		srcdir=${CMAKE_CURRENT_SOURCE_DIR}
		builddir=${CMAKE_CURRENT_BINARY_DIR}
		bash ${CMAKE_CURRENT_SOURCE_DIR}/mlkem512-import-key-test.sh
)
