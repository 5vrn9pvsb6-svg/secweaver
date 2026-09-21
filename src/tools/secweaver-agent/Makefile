APP_NAME ?= secweaver-agent
VERSION_FILE := VERSION
VERSION ?= $(shell tr -d '[:space:]' < $(VERSION_FILE))

.PHONY: build build-cross build-smoke package test vet race fmt-check check integration-service-linux integration-service-windows clean

build:
	@test -n "$(VERSION)" || { echo "$(VERSION_FILE) is empty" >&2; exit 1; }
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION) -X secweaver-agent/pkg/auditportexecmon.version=$(VERSION)" -o $(APP_NAME) .

build-cross:
	VERSION=$(VERSION) ./scripts/build-cross.sh

package:
	VERSION=$(VERSION) ./scripts/package-release.sh

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

build-smoke:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...

check: fmt-check vet test race build-smoke

integration-service-linux:
	sudo ./integration/service-upgrade/linux-systemd.sh

integration-service-windows:
	powershell.exe -ExecutionPolicy Bypass -File .\integration\service-upgrade\windows-scm.ps1

clean:
	rm -f $(APP_NAME)
