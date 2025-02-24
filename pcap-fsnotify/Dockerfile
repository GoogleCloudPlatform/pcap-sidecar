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


FROM --platform=linux/amd64 golang:1.22.4-bookworm AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG BIN_NAME=pcap_fsn

WORKDIR /app

COPY ./pcap-fsnotify/go.mod go.mod
COPY ./pcap-fsnotify/go.sum go.sum
COPY ./pcap-fsnotify/main.go main.go

RUN go install mvdan.cc/gofumpt@latest

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN gofumpt -l -w ./main.go
RUN go mod tidy -compat=1.22.4
RUN go mod download
RUN go build -v -o /app/bin/${BIN_NAME}

FROM scratch AS releaser
COPY --link --from=builder /app/bin/${BIN_NAME} /
