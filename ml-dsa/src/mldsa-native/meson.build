# Meson build file for mldsa-native integration

dilithium_mldsa = files([
	'mldsa_native_all.c',
	'mldsa_native_all.S',
	'dilithium_signature_api_mldsa.c'
])

mldsa_native_include_dirs = include_directories('mldsa-native', '.', '..')

if get_option('dilithium_87').enabled()
	leancrypto_dilithium_87_mldsa_lib = static_library(
		'leancrypto_dilithium_87_mldsa_lib',
		[ dilithium_mldsa ],
		include_directories: [ include_dirs, include_internal_dirs, mldsa_native_include_dirs ],
		c_args: '-DLC_DILITHIUM_TYPE_87'
	)
	leancrypto_support_libs += leancrypto_dilithium_87_mldsa_lib
endif

if get_option('dilithium_65').enabled()
	leancrypto_dilithium_65_mldsa_lib = static_library(
		'leancrypto_dilithium_65_mldsa_lib',
		[ dilithium_mldsa ],
		include_directories: [ include_dirs, include_internal_dirs, mldsa_native_include_dirs ],
		c_args: '-DLC_DILITHIUM_TYPE_65'
	)
	leancrypto_support_libs += leancrypto_dilithium_65_mldsa_lib
endif

if get_option('dilithium_44').enabled()
	leancrypto_dilithium_44_mldsa_lib = static_library(
		'leancrypto_dilithium_44_mldsa_lib',
		[ dilithium_mldsa ],
		include_directories: [ include_dirs, include_internal_dirs, mldsa_native_include_dirs ],
		c_args: '-DLC_DILITHIUM_TYPE_44'
	)
	leancrypto_support_libs += leancrypto_dilithium_44_mldsa_lib
endif
