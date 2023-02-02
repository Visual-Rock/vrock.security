src = [
    'encryption/RC4.cpp',
    'encryption/AES.cpp',

    'hash/MD5.cpp',
    'hash/SHA2.cpp'
]

header = [
    '../include/vrock/security/encryption/RC4.hpp',
    '../include/vrock/security/encryption/AES.hpp',

    '../include/vrock/security/hash/MD5.hpp'
]

public_header = include_directories('../include')

# https://gist.github.com/HE-Wenjian/f40807d24e33a5df1d46230c7e3b3844
conan = find_program('conan', required: false)
search_deps = {
    'vrockutils': { 'wrap': ['vrockutils', 'vrockutils_dep'] },
    'cryptopp': { 'conan': 'cryptopp/8.7.0@', 'buildtype': 'Debug' }
}
deps = []
foreach pkg_name, conf : search_deps
    # first try system
    pkg = dependency(pkg_name, fallback: conf.get('wrap', ['_', '_']), 
        required: not conf.has_key('conan'), kwargs: conf.get('kwargs',{}),
        default_options: conf.get('default_options',[]) )
    # check conan if configured
    if not pkg.found() and conf.has_key('conan')
        assert(conan.found(), 'conan not found not all dependencies could be satisfied')
        module_path = meson.current_build_dir() / 'conan-cmake' / pkg_name
        conan_buildtype= conf.get('buildtype', get_option('debug') ? 'Debug' : 'Release')
        run_command(conan, 'install', conf['conan'], '-if', module_path,
            '-g', 'cmake_find_package', '-s:b', 'build_type=' + conan_buildtype, check: true)
        deps += dependency(pkg_name, kwargs: conf.get('kwargs',{}), 
            method: 'cmake', cmake_module_path : module_path)
    else
        deps += pkg
    endif

endforeach


securitylib = static_library(meson.project_name(),
    src,
    include_directories: public_header,
    dependencies: deps
)

securitylib_dep = declare_dependency(
    include_directories: public_header,
    link_with: securitylib,
    dependencies: deps
)

set_variable(meson.project_name() + '_dep', securitylib_dep)
install_headers(header, subdir: 'vrock/security')

pkg_mod = import('pkgconfig')
pkg_mod.generate(
  name : meson.project_name(),
  filebase : meson.project_name(),
  description : '',
  subdirs : meson.project_name(),
  libraries : securitylib,
)
