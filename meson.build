# Optional Meson build, for distributions that prefer it over pip.
#   meson setup _build --prefix=/usr && meson install -C _build
project(
  'logread',
  version: '1.0.0',
  meson_version: '>= 0.59.0',
  license: 'GPL-3.0-or-later',
)

python = import('python').find_installation('python3')
gnome = import('gnome')

app_id = 'io.github.isaluki.LogRead'
pkgdatadir = get_option('prefix') / get_option('datadir') / meson.project_name()

install_subdir(
  'src/logread',
  install_dir: python.get_install_dir(),
  exclude_directories: ['__pycache__', 'core/__pycache__', 'ui/__pycache__'],
)

configure_file(
  input: 'logread.in',
  output: 'logread',
  configuration: configuration_data({'PYTHON': python.full_path()}),
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
)

install_data(
  'data' / app_id + '.desktop',
  install_dir: get_option('datadir') / 'applications',
)
install_data(
  'data' / app_id + '.metainfo.xml',
  install_dir: get_option('datadir') / 'metainfo',
)
install_data(
  'data/icons/hicolor/scalable/apps' / app_id + '.svg',
  install_dir: get_option('datadir') / 'icons/hicolor/scalable/apps',
)
install_data(
  'data/icons/hicolor/symbolic/apps' / app_id + '-symbolic.svg',
  install_dir: get_option('datadir') / 'icons/hicolor/symbolic/apps',
)

gnome.post_install(
  gtk_update_icon_cache: true,
  update_desktop_database: true,
)

test(
  'unit',
  python,
  args: ['-m', 'unittest', 'discover', '-s', 'tests'],
  env: {'PYTHONPATH': meson.current_source_dir() / 'src'},
  workdir: meson.current_source_dir(),
)
