# Stage 1: Build the binary
FROM --platform=linux/arm64 rust:slim AS builder

ENV TARGET aarch64-unknown-linux-musl
RUN rustup target add "$TARGET"

WORKDIR /usr/src/caetun

# Copy the source code
COPY . .

# Build the binary
RUN cargo build --release --locked --target "$TARGET" \
    && mv "/usr/src/caetun/target/$TARGET/release/caetun" . \
    && mv "/usr/src/caetun/target/$TARGET/release/caetun-conf" .

# Stage 2: Create the runtime container
FROM --platform=linux/arm64 alpine:latest

# Install required packages
RUN apk add --no-cache \
    iproute2 \
    jq \
    libcap \
    bash

# Copy the built binary from the builder stage
COPY --from=builder /usr/src/caetun/caetun /usr/local/bin/
COPY --from=builder /usr/src/caetun/caetun-conf /usr/local/bin/

# Set capabilities for the caetun binary
RUN setcap cap_net_admin=eip /usr/local/bin/caetun

# Copy the configuration files
COPY --from=builder /usr/src/caetun/server.conf /etc/caetun/server.conf
COPY --from=builder /usr/src/caetun/client1.conf /etc/caetun/client1.conf
COPY --from=builder /usr/src/caetun/client2.conf /etc/caetun/client2.conf

# Copy the server and client scripts
COPY --from=builder /usr/src/caetun/server.sh /usr/local/bin/server.sh
COPY --from=builder /usr/src/caetun/client.sh /usr/local/bin/client.sh
RUN chmod +x /usr/local/bin/server.sh /usr/local/bin/client.sh

# Set the mode
ENV MODE server

# Create a wrapper script to choose between server and client
COPY <<EOF /usr/local/bin/start.sh
#!/bin/bash
echo "Current MODE: \${MODE}"
if [ \${MODE} = "server" ]; then
    exec /usr/local/bin/server.sh
elif [ \${MODE} = "client" ]; then
    exec /usr/local/bin/client.sh "\$@"
else
    echo "Please set MODE environment variable to 'server' or 'client'"
    exit 1
fi
EOF

RUN chmod +x /usr/local/bin/start.sh

WORKDIR /usr/local/bin

# Set the entrypoint
ENTRYPOINT ["start.sh"]
