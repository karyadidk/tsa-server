# Use Debian as the base image
FROM debian:latest

# Set the working directory
WORKDIR /app

# Install necessary dependencies
RUN apt-get update && apt-get install -y curl build-essential pkg-config libssl-dev \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y

# Set Rust and Cargo in PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy the Cargo files first to cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# # Build the Rust project in release mode
# RUN cargo build --release || echo "Build failed, continuing..."

# Expose the API port
EXPOSE 2580

# Set the default command to run the Rust binary
CMD ["sh", "-c", "cargo build --release && ./target/release/tsa"]