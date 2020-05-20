FROM node:10-alpine

ENV HOME=/root

RUN apk add --no-cache \
    bash \
    automake \
    make gcc g++ linux-headers eudev-dev \
    git \
    curl \
    python \
    libusb-dev

RUN git clone https://github.com/celo-org/celo-monorepo
RUN cd celo-monorepo && yarn
RUN cd celo-monorepo && cd packages/utils && yarn build && cd ../dev-utils && yarn build && cd ../protocol && yarn build && cd ../contractkit && yarn build && cd ../cli && yarn build
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH $HOME/.cargo/bin:$PATH
RUN rustup install 1.42.0 && rustup default 1.42.0
RUN git clone https://github.com/celo-org/celo-threshold-bls-rs
RUN cd celo-threshold-bls-rs/crates/dkg-cli && RUSTFLAGS="-C target-feature=-crt-static" cargo build --release && cd / && cp celo-threshold-bls-rs/target/release/dkg /dkgbin && rm -rf celo-threshold-bls-rs/target


FROM node:10-alpine
RUN apk add --no-cache \
    bash \
    automake \
    make gcc g++ linux-headers eudev-dev \
    git \
    curl \
    python \
    libusb-dev

COPY --from=0 /celo-monorepo/package.json /celo-monorepo/yarn.lock  /celo-monorepo/lerna.json /monorepo/
COPY --from=0 /celo-monorepo/scripts /monorepo/scripts
COPY --from=0 /celo-monorepo/packages/cli/package.json /monorepo/packages/cli/
COPY --from=0 /celo-monorepo/packages/protocol/package.json /monorepo/packages/protocol/
COPY --from=0 /celo-monorepo/packages/typescript/package.json /monorepo/packages/typescript/
COPY --from=0 /celo-monorepo/packages/dev-utils/package.json /monorepo/packages/dev-utils/
COPY --from=0 /celo-monorepo/packages/contractkit/package.json /monorepo/packages/contractkit/
COPY --from=0 /celo-monorepo/packages/utils/package.json /monorepo/packages/utils/

RUN cd /monorepo && cd packages/cli && yarn install && yarn add @types/prompts && cd ../.. && yarn cache clean

COPY --from=0 /celo-monorepo/packages/cli /monorepo/packages/cli/
COPY --from=0 /celo-monorepo/packages/protocol /monorepo/packages/protocol/
COPY --from=0 /celo-monorepo/packages/typescript /monorepo/packages/typescript/
COPY --from=0 /celo-monorepo/packages/dev-utils /monorepo/packages/dev-utils/
COPY --from=0 /celo-monorepo/packages/contractkit /monorepo/packages/contractkit/
COPY --from=0 /celo-monorepo/packages/utils /monorepo/packages/utils/

RUN cd /monorepo && yarn build

COPY --from=0 /celo-monorepo/packages/cli/node_modules /cli/node_modules
COPY --from=0 /dkgbin /
ENV CELO=/monorepo/packages/cli/bin/run
ENV DKG=/dkgbin
ADD run_dkg.sh /
WORKDIR /dkg
ENTRYPOINT [ "../run_dkg.sh" ]
