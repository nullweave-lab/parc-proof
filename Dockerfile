FROM rust:1.82-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin parc-attester

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home parc
COPY --from=build /src/target/release/parc-attester /usr/local/bin/parc-attester
USER parc
WORKDIR /home/parc
ENTRYPOINT ["/usr/local/bin/parc-attester"]
