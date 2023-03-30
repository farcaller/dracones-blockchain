FROM docker.io/paritytech/ci-linux:production as builder
WORKDIR /node-dracones
COPY . .
RUN cargo build --locked --release


FROM docker.io/library/ubuntu:20.04
COPY --from=builder /node-dracones/target/release/node-dracones /usr/local/bin
RUN useradd -m -u 1000 -U -s /bin/sh -d / node-dev
USER node-dev
EXPOSE 30333 9933 9944 9615
ENTRYPOINT ["/usr/local/bin/node-dracones"]
