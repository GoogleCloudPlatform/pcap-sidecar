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

ARG GOLANG_VERSION='1.23.4'

FROM golang:${GOLANG_VERSION}-alpine AS builder

ARG GIT_VERSION='2.47.1-r0'
ARG PATCH_VERSION='2.7.6-r10'

ARG GCSFUSE_VERSION='2.7.0'
ARG GCSFUSE_REPO='/run/gcsfuse'

RUN apk add --no-cache --update git patch

COPY ./gcsfuse/patch /patch

# clone `gcsfuse` at specific version
RUN git clone --depth 1 --branch v${GCSFUSE_VERSION} \
  https://github.com/GoogleCloudPlatform/gcsfuse.git ${GCSFUSE_REPO}

# patch files
RUN patch ${GCSFUSE_REPO}/internal/fs/fs.go /patch/v${GCSFUSE_VERSION}/internal/fs/fs.go

WORKDIR ${GCSFUSE_REPO}/

# build patched `gcsfuse`
RUN git config --global pager.diff false \
  && git --no-pager diff ${GCSFUSE_REPO}/internal/fs/fs.go

RUN go install ./tools/build_gcsfuse \
  && build_gcsfuse . /tmp "$(git log -1 --format=format:'%H')"

FROM scratch AS releaser

COPY --link --from=builder /tmp/bin/gcsfuse /
COPY --link --from=builder /tmp/sbin/mount.gcsfuse /
