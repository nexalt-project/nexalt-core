package=xcb_proto
$(package)_version=1.10
$(package)_download_path=https://xcb.freedesktop.org/dist
$(package)_file_name=xcb-proto-$($(package)_version).tar.bz2
$(package)_sha256_hash=7ef40ddd855b750bc597d2a435da21e55e502a0fefa85b274f2c922800baaf05

# Fix for Python 3.12+ compatibility - replace deprecated imp module
define $(package)_preprocess_cmds
  sed -i 's/import sys, os, py_compile, imp/import sys, os, py_compile\ntry:\n    import importlib.util as imp_util\nexcept ImportError:\n    import imp as imp_util/g' py-compile && \
  sed -i 's/if hasattr(imp, '\''get_tag'\''):/if hasattr(imp_util, '\''cache_from_source'\''):\n        py_compile.compile(filepath, imp_util.cache_from_source(filepath), path)\n    elif hasattr(imp_util, '\''get_tag'\''):/g' py-compile && \
  sed -i 's/if hasattr(imp, '\''get_tag'\''):/if hasattr(imp_util, '\''cache_from_source'\''):\n        py_compile.compile(filepath, imp_util.cache_from_source(filepath, False), path)\n    elif hasattr(imp_util, '\''get_tag'\''):/g' py-compile && \
  sed -i 's/imp\.cache_from_source/imp_util.cache_from_source/g' py-compile
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
  find -name "*.pyc" -delete && \
  find -name "*.pyo" -delete
endef
