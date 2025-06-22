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

ARG GOLANG_VERSION='1.24.0'
ARG LIBPCAP_VERSION='1.10.5'
ARG TCPDUMP_VERSION='4.99.5'

FROM --platform=linux/amd64 pcap-golang:libpcap-v${LIBPCAP_VERSION}_tcpdump-v${TCPDUMP_VERSION} AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG BIN_NAME='tcpdumpw'

# include PCAP CLI
WORKDIR /app/pcap-cli

COPY ./pcap-cli/go.mod go.mod
COPY ./pcap-cli/go.sum go.sum
COPY ./pcap-cli/internal internal
COPY ./pcap-cli/pkg pkg
COPY ./pcap-cli/schema schema

WORKDIR /app/tcpdumpw

COPY ./tcpdumpw/go.mod go.mod
COPY ./tcpdumpw/go.sum go.sum
COPY ./tcpdumpw/main.go main.go
COPY ./tcpdumpw/pkg pkg

ENV GOOS=linux
ENV GOARCH=amd64

RUN go install mvdan.cc/gofumpt@latest \
  && gofumpt -l -w ./main.go \
  && go mod tidy -compat="${GOLANG_VERSION}" \
  && go mod download \
  && go build -a -v -tags json -o /app/tcpdumpw/bin/${BIN_NAME} main.go

FROM scratch AS releaser
COPY --link --from=builder /app/tcpdumpw/bin/${BIN_NAME} /
