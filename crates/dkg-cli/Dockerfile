FROM ubuntu:18.04

RUN rm /bin/sh && ln -s /bin/bash /bin/sh
ENV HOME=/root

RUN apt-get update && apt-get install -y \
    automake \
    build-essential \
    git \
    curl \
    python \
    libusb-1.0-0-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash
ENV NVM_DIR $HOME/.nvm
ENV NODE_VERSION 10.16.3
RUN . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH
RUN npm install -g yarn
RUN git clone https://github.com/celo-org/celo-monorepo
RUN cd celo-monorepo && yarn && yarn build && cd packages/cli && yarn build
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV CELO=/celo-monorepo/packages/cli/bin/run
ENV PATH $HOME/.cargo/bin:$PATH
RUN rustup install 1.42.0 && rustup default 1.42.0
RUN git clone https://github.com/celo-org/celo-threshold-bls-rs
RUN cd celo-threshold-bls-rs/crates/dkg-cli && cargo build --release && cd / && cp celo-threshold-bls-rs/target/release/dkg /dkgbin && rm -rf celo-threshold-bls-rs/target
ENV DKG=/dkgbin
ADD run_dkg.sh /
WORKDIR /dkg
ENTRYPOINT [ "../run_dkg.sh" ]
