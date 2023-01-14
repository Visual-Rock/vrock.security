if get_option('tests')

test_src = [
    'encryption/rc4.test.cpp',
    'encryption/aes.test.cpp'
]

gtest_proj = subproject('gtest')
gtest_dep = gtest_proj.get_variable('gtest_main_dep')


tests = executable(
    'tests', test_src,
    dependencies: [ gtest_dep, securitylib_dep ],
    include_directories: include_directories('../include')
)

test('gtest tests', tests)

endif