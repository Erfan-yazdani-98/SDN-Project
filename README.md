# E3 – Packet Size Analyzer

An eBPF/XDP‑based packet size analyzer that computes, in real time, the average packet size on a network interface and groups statistics by Ethernet protocol.

## Features

- **Basic**  
  - Track and report **real‑time average packet size** across all traffic.

- **Intermediate**  
  - **Group statistics by protocol** (e.g. IPv4, IPv6, ARP) and compute per‑protocol averages.

## Requirements

- **Linux kernel** ≥ 4.8 (with BPF and XDP support)  
- **LLVM/Clang** (for compiling eBPF programs)  
- **libbpf-dev** (libbpf headers and development files)  
- **bpftool** (for inspecting and pinning maps)  
- **gcc**, **make** (for user‑space loader)  
- **Root privileges** to load the XDP program  


## Building

Follow these five steps to compile the eBPF program and user‑space loader, verify the outputs, and (optionally) containerize the build.

1. **Prepare Your Environment**  
   Install required packages on your host (or inside your Podman container):
   ```bash
   sudo apt update
   sudo apt install -y \
     clang llvm libelf-dev libbpf-dev bpftool \
     gcc make iproute2 procps
2. **Clone & Navigate**  
   Clone (or update) your fork of `kernel-playground` and enter the example directory:  
   ```bash
   git clone https://github.com/Erfan-yazdani-98/kernel-playground.git
   cd kernel-playground/examples/xdp/e3_packet_size_analyzer
3. **Clean & Compile the eBPF Program**  
   Remove old artifacts and build the BPF object:  
   ```bash
   make clean
   make netprog.bpf.o

  
