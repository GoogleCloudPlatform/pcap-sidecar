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


ARG LIBPCAP_VERSION='1.10.5'
ARG TCPDUMP_VERSION='4.99.5'

FROM pcap-base:libpcap-v${LIBPCAP_VERSION}_tcpdump-v${TCPDUMP_VERSION} AS base

FROM --platform=linux/amd64 ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG GCSFUSE_VERSION='2.7.0'

WORKDIR /app

USER 0:0

RUN apt-get -qq update  > /dev/null \
    && apt-get -qq -y install ca-certificates tzdata fuse curl gawk jq iproute2 > /dev/null \
    && apt-get -qq clean > /dev/null

COPY --from=base /dist/bin/ /usr/bin/
COPY --from=base /dist/lib/ /lib/x86_64-linux-gnu/

RUN ldconfig -v

RUN curl -o /gcsfuse.deb -L \
    https://github.com/GoogleCloudPlatform/gcsfuse/releases/download/v${GCSFUSE_VERSION}/gcsfuse_${GCSFUSE_VERSION}_amd64.deb \
    && dpkg -i --force-all /gcsfuse.deb && rm -vf /gcsfuse.deb
