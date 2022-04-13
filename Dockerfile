# MIT License
#
# (C) Copyright 2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Build base just has the packages installed we need.
FROM artifactory.algol60.net/docker.io/library/golang:1.16-alpine AS build-base

RUN set -ex \
    && apk -U upgrade \
    && apk add build-base

# Base copies in the files we need to test/build.
FROM build-base AS base

RUN go env -w GO111MODULE=auto

# Copy all the necessary files to the image.
COPY cmd        $GOPATH/src/github.com/Cray-HPE/hms-creds-control/cmd
COPY internal   $GOPATH/src/github.com/Cray-HPE/hms-creds-control/internal
COPY vendor     $GOPATH/src/github.com/Cray-HPE/hms-creds-control/vendor

### Build Stage ###
FROM base AS builder

RUN set -ex \
    && go build -v -o /usr/local/bin/creds-control github.com/Cray-HPE/hms-creds-control/cmd/hms_creds_control


## Final Stage ###
FROM artifactory.algol60.net/docker.io/alpine:3.13 AS deploy-base

LABEL maintainer="Hewlett Packard Enterprise"

COPY --from=builder /usr/local/bin/creds-control /usr/local/bin
ENV HSM_BASE_PATH="/hsm/v1"

RUN set -ex \
    && apk -U upgrade \
    && apk add --no-cache \
        curl

# nobody 65534:65534
USER 65534:65534

CMD ["sh", "-c", "creds-control"]
