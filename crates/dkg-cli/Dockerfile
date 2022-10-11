FROM circleci/rust:1.44.0

ENV HOME=/home/circleci
ENV PATH=$HOME/bin:$PATH

RUN cd $HOME && git clone https://github.com/celo-org/celo-threshold-bls-rs
RUN mkdir $HOME/bin && wget -q https://github.com/ethereum/solidity/releases/download/v0.6.6/solc-static-linux -O $HOME/bin/solc && chmod u+x $HOME/bin/solc && solc --version
RUN cd $HOME && cd celo-threshold-bls-rs/crates/dkg-cli && RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

FROM ubuntu:18.04
COPY --from=0 /home/circleci/celo-threshold-bls-rs/target/release/dkg-cli /dkgbin
WORKDIR /dkg
ENTRYPOINT [ "/dkgbin" ]
