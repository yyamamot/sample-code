BPF_SRC=addr_restrictions.bpf.c
SRC=addr_restriction.go
TARGET=addr_restriction

.PHONY: all
all: bpf_bpfel.go
	go build -o ${TARGET} -trimpath -ldflags "-s -w" ${SRC} bpf_bpfel.go

bpf_bpfel.go: ${BPF_SRC}
	go generate ${SRC}

.PHONY: run
run: all
	sudo ./${TARGET}

.PHONY: clean
clean:
	rm -f ${TARGET}

.PHONY: format
format:
	clang-format -i ${BPF_SRC}
	go fmt ./...

.PHONY: lint
lint:
	golangci-lint run ./...
