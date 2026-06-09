FROM ubuntu:22.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    libssl-dev \
    libargon2-dev \
    libfuse-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source tree
COPY . .

# Build the project
RUN mkdir build && cd build && cmake .. && make

# Command to run the VFS server
CMD ["./build/svf"]
