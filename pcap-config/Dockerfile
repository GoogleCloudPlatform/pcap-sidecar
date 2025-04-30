# syntax=docker/dockerfile:1.4
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG GOLANG_VERSION='1.23.7'

FROM --platform=linux/amd64 golang:${GOLANG_VERSION}-bookworm AS builder

ARG PCAP_VERSION='0.0.0'
ARG PCAP_COMMIT_ID='unknown'
ARG GOLANG_VERSION='1.23.7'

ARG DEBIAN_FRONTEND=noninteractive
ARG BIN_NAME=pcapcfg

ARG GO_MODULE='github.com/GoogleCloudPlatform/pcap-sidecar/pcap-config'

WORKDIR /app

COPY ./pcap-config/go.mod go.mod
COPY ./pcap-config/go.sum go.sum
COPY ./pcap-config/main.go main.go
COPY ./pcap-config/pkg/ pkg/
COPY ./pcap-config/internal/ internal/

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go install mvdan.cc/gofumpt@latest
RUN gofumpt -l -w .

RUN go mod tidy -compat="${GOLANG_VERSION}"
RUN go mod download
RUN go build -v \
  -ldflags "-X ${GO_MODULE}/internal/config.Version=v${PCAP_VERSION} -X ${GO_MODULE}/internal/config.Build=${PCAP_COMMIT_ID}" \
  -o /app/bin/${BIN_NAME}

FROM scratch AS releaser
COPY --link --from=builder /app/bin/${BIN_NAME} /
