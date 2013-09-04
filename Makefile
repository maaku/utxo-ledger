ROOT=$(shell pwd)
CACHE_ROOT=${ROOT}/.cache
PYENV=${ROOT}/.pyenv
CONF=${ROOT}/conf
APP_NAME=utxo-ledger

-include Makefile.local

.PHONY: all
all: ${PYENV}/.stamp-h

.PHONY: shell
shell: all
	"${PYENV}"/bin/ipython

.PHONY: mostlyclean
mostlyclean:
	-rm -rf dist
	-rm -rf build
	-rm -rf .coverage

.PHONY: clean
clean: mostlyclean
	-rm -rf "${PYENV}"

.PHONY: distclean
distclean: clean
	-rm -rf "${CACHE_ROOT}"
	-rm -rf Makefile.local

.PHONY: maintainer-clean
maintainer-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'

# ===--------------------------------------------------------------------===

.PHONY: dist
dist:
	"${PYENV}"/bin/python setup.py sdist

# ===--------------------------------------------------------------------===

${CACHE_ROOT}/virtualenv/virtualenv-1.10.tar.gz:
	mkdir -p "${CACHE_ROOT}"/virtualenv
	curl -L 'https://pypi.python.org/packages/source/v/virtualenv/virtualenv-1.10.tar.gz' >'$@'

${PYENV}/.stamp-h: ${ROOT}/requirements.txt ${CONF}/requirements*.txt ${CACHE_ROOT}/virtualenv/virtualenv-1.10.tar.gz
	# Because build and run-time dependencies are not thoroughly tracked,
	# it is entirely possible that rebuilding the development environment
	# on top of an existing one could result in a broken build. For the
	# sake of consistency and preventing unnecessary, difficult-to-debug
	# problems, the entire development environment is rebuilt from scratch
	# everytime this make target is selected.
	${MAKE} clean
	
	# The ${PYENV} directory, if it exists, was removed above. The
	# PyPI cache is nonexistant if this is a freshly checked-out
	# repository, or if the `distclean` target has been run.  This
	# might cause problems with build scripts executed later which
	# assume their existence, so they are created now if they don't
	# already exist.
	mkdir -p "${PYENV}"
	mkdir -p "${CACHE_ROOT}"/pypi
	
	# `virtualenv` is used to create a separate Python installation for
	# this project in `${PYENV}`.
	tar \
	    -C "${CACHE_ROOT}"/virtualenv --gzip \
	    -xf "${CACHE_ROOT}"/virtualenv/virtualenv-1.10.tar.gz
	python "${CACHE_ROOT}"/virtualenv/virtualenv-1.10/virtualenv.py \
	    --clear \
	    --distribute \
	    --never-download \
	    --prompt="(${APP_NAME}) " \
	    "${PYENV}"
	-rm -rf "${CACHE_ROOT}"/virtualenv/virtualenv-1.10
	
	# readline is installed here to get around a bug on Mac OS X
	# which is causing readline to not build properly if installed
	# from pip, and the fact that a different package must be used
	# to support it on Windows/Cygwin.
	if [ "x`uname -o`" == "xCygwin" ]; then \
	    "${PYENV}"/bin/pip install pyreadline; \
	else \
	    "${PYENV}"/bin/easy_install readline; \
	fi
	
	# pip is used to install Python dependencies for this project.
	for reqfile in "${ROOT}"/requirements.txt \
	               "${CONF}"/requirements*.txt; do \
	    CFLAGS=-I/opt/local/include LDFLAGS=-L/opt/local/lib \
	    "${PYENV}"/bin/python "${PYENV}"/bin/pip install \
	        --download-cache="${CACHE_ROOT}"/pypi \
	        -r "$$reqfile"; \
	done
	
	# All done!
	touch "${PYENV}"/.stamp-h

#
# End of File
#
