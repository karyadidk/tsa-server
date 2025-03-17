# Use RHEL-based image (Rocky Linux as a free alternative)
FROM rockylinux:9

# Set the working directory
WORKDIR /app

# Install necessary dependencies
RUN dnf install -y --allowerasing curl gcc make pkg-config openssl-devel \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y

# Set Rust and Cargo in PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy the Cargo files first to cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the Rust project in release mode
RUN cargo build --release || echo "Build failed, continuing..."

# Expose the API port
EXPOSE 2580

# Set the default command to run the Rust binary
CMD ["sh", "-c", "cargo build --release && ./target/release/tsa"]
