FROM alpine

LABEL maintainer="ebft-dev"
ENV GOPATH=/go
ENV PATH=$GOPATH/bin/:$PATH
ADD . /app
ADD ./tools/Btcwallet /root/.btcwallet
ADD ./tools/Btcd /root/.btcd
WORKDIR /app

RUN apk add --no-cache bash git go musl-dev \
  # install btcd
  && go build \
  && go install . ./cmd/... \
  # install btcwallet
  && cd /\
  && git clone https://github.com/btcsuite/btcwallet.git \
  && cd btcwallet \
  && GO111MODULE=on go install -v . ./cmd/... \
  # clean
  && apk del git go musl-dev \
  && rm -rf /apk /tmp/* /var/cache/apk/* $GOPATH/src/*

EXPOSE 18554 18555 18556
CMD ["btcd", "--help"]
