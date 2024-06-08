FROM rust:latest

WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

RUN mkdir src && echo 'fn main() { println!("Hello, world!"); }' > src/main.rs
RUN cargo install --path .

COPY .cargo .cargo
COPY src src

RUN cargo build --release