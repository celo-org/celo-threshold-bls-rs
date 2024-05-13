FROM rust:1.78.0

ENV HOME=/root
ENV PATH=$HOME/bin:$PATH

RUN cd $HOME && git clone https://github.com/trilitech/dkg-tooling
RUN mkdir $HOME/bin && wget -q https://github.com/ethereum/solidity/releases/download/v0.8.25/solc-static-linux -O $HOME/bin/solc && chmod u+x $HOME/bin/solc && solc --version
RUN cd $HOME && cd dkg-tooling/crates/dkg-cli && RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

FROM ubuntu:22.04
COPY --from=0 /home/root/dkg-tooling/target/release/dkg-cli /usr/bin
ENTRYPOINT [ "dkg-cli" ]
