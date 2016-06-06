.PHONY: com.docker.slirp.exe com.docker.slirp install uninstall

TARGETS :=
ifeq ($(OS),Windows_NT)
	TARGETS += com.docker.slirp.exe
else
	TARGETS += com.docker.slirp
endif

all: $(TARGETS)

EXEDIR=C:\projects\vpnkit

com.docker.slirp:
	$(MAKE) -C src/com.docker.slirp

depends:
	opam repo list | grep com-docker-slirp || opam repo add com-docker-slirp .
	opam update com-docker-slirp
	opam pin add -n proto-vmnet src/proto-vmnet -y
	opam pin add -n ofs src/ofs -y
	opam pin add -n hostnet src/hostnet -y
	opam pin add -n osx-daemon src/osx-daemon -y
	opam pin add -n osx-hyperkit src/osx-hyperkit -y
ifeq ($(OS),Windows_NT)
	opam pin add -n slirp src/com.docker.slirp.exe -y
else
	opam pin add -n slirp src/com.docker.slirp -y
endif
	opam depext -u slirp
	opam install --deps-only slirp -y

com.docker.slirp.exe:
	cd src/com.docker.slirp.exe && \
	oasis setup && \
	./configure && \
	make && \
	cp _build/src/main.native com.docker.slirp.exe

install:
	cp src/com.docker.slirp.exe/com.docker.slirp.exe '$(EXEDIR)'
	cp src/com.docker.slirp.exe/register.ps1 '$(EXEDIR)'

uninstall:
	echo uninstall not implemented
