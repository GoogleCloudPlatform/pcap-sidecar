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

ARG PCAP_VERSION='0.0.0'
ARG GOLANG_VERSION='1.23.7'
ARG LIBPCAP_VERSION='1.10.5'
ARG TCPDUMP_VERSION='4.99.5'

FROM pcap-base:v${PCAP_VERSION}_libpcap-v${LIBPCAP_VERSION}_tcpdump-v${TCPDUMP_VERSION} AS base

ARG GOLANG_VERSION='1.23.7'

FROM --platform=linux/amd64 golang:${GOLANG_VERSION}-bookworm

USER 0:0

COPY --from=base /dist/bin/ /usr/bin/
COPY --from=base /dist/lib/ /lib/x86_64-linux-gnu/
COPY --from=base /dist/include/ /usr/include/

RUN ldconfig -v
