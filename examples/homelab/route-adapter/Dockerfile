FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml .
COPY src/ src/
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/lattice-route-adapter /usr/local/bin/
ENTRYPOINT ["lattice-route-adapter"]
