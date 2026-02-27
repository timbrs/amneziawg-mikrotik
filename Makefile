VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE_NAME = awg-proxy
BUILD_DIR = builds

.PHONY: build test clean docker-arm64 docker-arm docker-armv5 docker-amd64 docker-all \
	docker-arm64-7.20-docker docker-arm-7.20-docker docker-armv5-7.20-docker docker-amd64-7.20-docker docker-all-7.20-docker \
	binary-arm64 binary-arm binary-armv5 binary-amd64 binary-all

LDFLAGS = -s -w -X main.version=$(VERSION)

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(IMAGE_NAME) .

test:
	go test -v -race ./...

clean:
	rm -rf $(BUILD_DIR)

docker-arm64:
	@mkdir -p $(BUILD_DIR)
	docker buildx build --platform linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--output type=oci,dest=$(BUILD_DIR)/$(IMAGE_NAME)-arm64.tar \
		-t $(IMAGE_NAME):$(VERSION)-arm64 .
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-arm64.tar

docker-arm:
	@mkdir -p $(BUILD_DIR)
	docker buildx build --platform linux/arm/v7 \
		--build-arg VERSION=$(VERSION) \
		--output type=oci,dest=$(BUILD_DIR)/$(IMAGE_NAME)-arm.tar \
		-t $(IMAGE_NAME):$(VERSION)-arm .
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-arm.tar

docker-armv5:
	@mkdir -p $(BUILD_DIR)
	docker buildx build --platform linux/arm/v5 \
		--build-arg VERSION=$(VERSION) \
		--output type=oci,dest=$(BUILD_DIR)/$(IMAGE_NAME)-armv5.tar \
		-t $(IMAGE_NAME):$(VERSION)-armv5 .
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-armv5.tar

docker-amd64:
	@mkdir -p $(BUILD_DIR)
	docker buildx build --platform linux/amd64 \
		--build-arg VERSION=$(VERSION) \
		--output type=oci,dest=$(BUILD_DIR)/$(IMAGE_NAME)-amd64.tar \
		-t $(IMAGE_NAME):$(VERSION)-amd64 .
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-amd64.tar

docker-all: docker-arm64 docker-arm docker-armv5 docker-amd64

docker-arm64-7.20-docker:
	@mkdir -p $(BUILD_DIR)
	VERSION=$(VERSION) scripts/mkdockertar.sh linux arm64 "" $(IMAGE_NAME):$(VERSION)-arm64 $(BUILD_DIR)/$(IMAGE_NAME)-arm64-7.20-Docker.tar
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-arm64-7.20-Docker.tar

docker-arm-7.20-docker:
	@mkdir -p $(BUILD_DIR)
	VERSION=$(VERSION) scripts/mkdockertar.sh linux arm 7 $(IMAGE_NAME):$(VERSION)-arm $(BUILD_DIR)/$(IMAGE_NAME)-arm-7.20-Docker.tar
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-arm-7.20-Docker.tar

docker-armv5-7.20-docker:
	@mkdir -p $(BUILD_DIR)
	VERSION=$(VERSION) scripts/mkdockertar.sh linux arm 5 $(IMAGE_NAME):$(VERSION)-armv5 $(BUILD_DIR)/$(IMAGE_NAME)-armv5-7.20-Docker.tar
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-armv5-7.20-Docker.tar

docker-amd64-7.20-docker:
	@mkdir -p $(BUILD_DIR)
	VERSION=$(VERSION) scripts/mkdockertar.sh linux amd64 "" $(IMAGE_NAME):$(VERSION)-amd64 $(BUILD_DIR)/$(IMAGE_NAME)-amd64-7.20-Docker.tar
	gzip -f $(BUILD_DIR)/$(IMAGE_NAME)-amd64-7.20-Docker.tar

docker-all-7.20-docker: docker-arm64-7.20-docker docker-arm-7.20-docker docker-armv5-7.20-docker docker-amd64-7.20-docker

binary-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(IMAGE_NAME)-linux-arm64 .

binary-arm:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(IMAGE_NAME)-linux-arm .

binary-armv5:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(IMAGE_NAME)-linux-armv5 .

binary-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(IMAGE_NAME)-linux-amd64 .

binary-all: binary-arm64 binary-arm binary-armv5 binary-amd64
