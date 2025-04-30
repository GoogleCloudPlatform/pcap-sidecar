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

ARG GOLANG_VERSION='1.23.7'

ARG DEBIAN_FRONTEND=noninteractive
ARG BIN_NAME=pcap

ARG GO_MODULE='github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli'

WORKDIR /app

ADD . /app

USER 0:0

RUN apt-get -qq update > /dev/null
RUN apt-get install -qq -y libpcap-dev 
RUN apt-get -qq clean > /dev/null

RUN go install mvdan.cc/gofumpt@latest
RUN go install golang.org/x/tools/cmd/stringer@latest

ENV GOOS=linux
ENV GOARCH=amd64

RUN go mod tidy -compat="${GOLANG_VERSION}"
RUN go mod download
RUN gofumpt -l -w ./cmd/
RUN gofumpt -l -w ./pkg/
RUN go generate ./pkg/...
RUN go build -a -v -tags json,proto -o /app/bin/${BIN_NAME} cmd/pcap.go

FROM scratch AS releaser
COPY --link --from=builder /app/bin/${BIN_NAME} /
