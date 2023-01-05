src = [
    'encryption/RC4.cpp'
]

header = [
    '../include/vrock/security/encryption/RC4.hpp'
]

public_header = include_directories('../include')

utilslib_dep = dependency('vrockutils', fallback: ['vrockutils', 'vrockutils_dep'], default_options: ['tests=true'])

securitylib = static_library(meson.project_name(), src,
    include_directories: public_header
)

securitylib_dep = declare_dependency(
    include_directories: public_header,
    link_with: securitylib,
    dependencies: utilslib_dep
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