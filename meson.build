project('vccert', 'c', 'cpp',
  version : '0.4.2-snapshot',
  default_options : ['c_std=gnu11', 'cpp_std=c++14', 'buildtype=release'],
  meson_version : '>=0.49.0'
)

message('Using build type: ' + get_option('buildtype'))

force_velo_toolchain = get_option('force_velo_toolchain')

if force_velo_toolchain
  cc = meson.get_compiler('c')
  cc_version = run_command(cc.cmd_array() + ['--version'], check : true).stdout()
  if not cc_version.contains('(velo)')
    error('force_velo_toolchain is set and you aren\'t using the velo toolchain.')
  endif
  cpp = meson.get_compiler('cpp')
  cpp_version = run_command(cpp.cmd_array() + ['--version'], check : true).stdout()
  if not cpp_version.contains('(velo)')
    error('force_velo_toolchain is set and you aren\'t using the velo toolchain.')
  endif
else
  warning('Not using the blessed velo gcc toolchain. Here be dragons.')
endif

add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'c')
add_project_arguments('-Wall', '-Werror', '-Wextra', language : 'cpp')

src = run_command('find', './src', '-name', '*.c', check : true).stdout().strip().split('\n')
test_src = run_command('find', './test', '-name', '*.cpp', check : true).stdout().strip().split('\n')

# GTest is currently only used on native x86 builds. Creating a disabler will disable the test exe and test target.
if meson.is_cross_build()
  minunit = disabler()
else
  minunit = dependency('minunit', main : true, required : true, fallback : ['minunit', 'minunit_dep'])
endif

vcmodel = dependency(
  'vcmodel',
  required : true,
  fallback : ['vcmodel', 'vcmodel_dep']
)

vpr = dependency(
  'vpr',
  required : true,
  fallback : ['vpr', 'vpr_dep']
)

vccrypt = dependency(
  'vccrypt',
  required : true,
  fallback : ['vccrypt', 'vccrypt_dep']
)

vccert_include = include_directories('include')
config_include = include_directories('.')

vccert_lib = static_library('vccert', src,
  dependencies : [vcmodel, vpr, vccrypt],
  include_directories : [vccert_include, config_include]
)

vccert_dep = declare_dependency(
  link_with : vccert_lib,
  include_directories : vccert_include
)

vccert_test = executable('testvccert', test_src,
  include_directories : [vccert_include, config_include],
  dependencies : [vpr, vccrypt, minunit],
  link_with : vccert_lib
)

test('vccert-test', vccert_test)

conf_data = configuration_data()
conf_data.set('VERSION', meson.project_version())
configure_file(
  input : 'config.h.in',
  output : 'config.h',
  configuration : conf_data
)

# vim: ts=2 sw=2 et colorcolumn=120
