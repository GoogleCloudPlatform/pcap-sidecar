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

FROM curlimages/curl AS provider

WORKDIR /app

RUN curl -s -L -o supervisord.zip https://github.com/ochinchina/supervisord/archive/refs/heads/master.zip \
    && unzip supervisord.zip -d ./tmp && mv ./tmp/*-master/* . && rm -rvf ./supervisord.zip ./tmp

FROM --platform=linux/amd64 golang:${GOLANG_VERSION}-bookworm AS builder

WORKDIR /app

COPY --from=provider /app/ .

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go generate && go build -v -a -tags release -ldflags '-extldflags "-static"' -o supervisord

FROM scratch AS releaser
COPY --link --from=builder /app/supervisord /
