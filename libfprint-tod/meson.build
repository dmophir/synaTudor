project('tudor-moc-tod', 'c',
  version : '0.1.0',
  default_options : ['warning_level=2', 'c_std=gnu11'])

# TOD-enabled libfprint (AUR libfprint-tod provides libfprint-2-tod-1.pc + tod_driversdir).
libfprint_tod_dep = dependency('libfprint-2-tod-1')
python_embed_dep  = dependency('python3-embed')
glib_dep          = dependency('glib-2.0')
gobject_dep       = dependency('gobject-2.0')
gio_dep           = dependency('gio-2.0')
gusb_dep          = dependency('gusb')

cc = meson.get_compiler('c')
dl_dep = cc.find_library('dl', required : false)   # dlopen (in libc on modern glibc)

# Where the pydrv `tudor` package lives (dir that contains it). Baked in as a default;
# overridable at runtime via $TUDOR_PYDRV_PATH. Default to the in-repo checkout for dev.
pydrv_path = get_option('pydrv_path')
if pydrv_path == ''
  pydrv_path = meson.project_source_root() / '..' / 'pydrv'
endif

tod_driversdir = libfprint_tod_dep.get_variable(pkgconfig : 'tod_driversdir')

tudor_moc_tod = shared_module('tudor_moc_tod',
  sources : [
    'src/device.c',
    'src/pyembed.c',
  ],
  name_prefix : 'lib',   # TOD loader only scans modules whose basename starts with "lib"
  c_args : [
    '-D_GNU_SOURCE',
    '-DTUDOR_PYDRV_PATH="' + pydrv_path + '"',
    '-Wno-unused-parameter',
  ],
  dependencies : [
    libfprint_tod_dep,
    python_embed_dep,
    glib_dep, gobject_dep, gio_dep, gusb_dep, dl_dep,
  ],
  install : true,
  install_dir : tod_driversdir,
)

udev_dep = dependency('udev', required : false)
if udev_dep.found()
  install_data('60-tudor-moc.rules',
    install_dir : udev_dep.get_variable(pkgconfig : 'udevdir') / 'rules.d')
endif

summary({
  'tod_driversdir' : tod_driversdir,
  'pydrv_path'     : pydrv_path,
})
