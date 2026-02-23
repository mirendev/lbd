.PHONY: all kernel commands clean deb rpm

all: kernel commands

kernel:
	$(MAKE) -C src

commands: bin
	go build -o bin/ ./cmd/...

bin:
	mkdir -p bin

deb:
	packaging/build-deb.sh

rpm:
	packaging/build-rpm.sh

clean:
	$(MAKE) -C src clean
	rm -rf bin dist
