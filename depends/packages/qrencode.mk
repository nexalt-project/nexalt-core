package=qrencode
$(package)_version=3.4.4
$(package)_download_path=https://github.com/fukuchi/libqrencode/archive/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=ab7cdf84e3707573a39e116ebd33faa513b306201941df3f5e691568368d87bf

define $(package)_set_vars
$(package)_config_opts=--disable-shared --without-tools --without-tests --disable-sdltest
$(package)_config_opts += --disable-gprof --disable-gcov --disable-mudflap
$(package)_config_opts += --disable-dependency-tracking --enable-option-checking
$(package)_config_opts_linux=--with-pic
$(package)_config_opts_android=--with-pic
endef

# Fix for autotools missing macros - Universal sed compatibility
define $(package)_preprocess_cmds
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub . && \
  sed -i.bak 's/AM_PATH_SDL/# AM_PATH_SDL/g' configure.ac && \
  sed -i.bak 's/AM_ICONV_LINK/# AM_ICONV_LINK/g' configure.ac && \
  rm -f configure.ac.bak && \
  autoreconf -fi
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm lib/*.la
endef
