btrdump = executable(
  'btrdump',
  'btrdump.c',
  include_directories : includes,
  link_with : [libalpm_a],
  dependencies : alpm_deps,
  install : false)

test('btrpkg',
  find_program('run.sh'),
  args : [btrdump.full_path(), meson.current_source_dir() / 'fixtures'],
  depends : btrdump,
  protocol : 'tap')
