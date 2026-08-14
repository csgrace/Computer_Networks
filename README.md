# Computer Networks (CS305)

[![SUSTech](https://img.shields.io/badge/SUSTech-CS305-blue)](https://www.sustech.edu.cn/)
[![Course](https://img.shields.io/badge/Course-Computer%20Networks-green)]()
[![Language](https://img.shields.io/badge/Language-Python-blue)]()
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen)]()

> **CS305 Course Project -- P2P File Transfer with Reliable Data Transport**
>
> A Python-based peer-to-peer file transfer system implementing custom reliable data transfer (RDT) protocols over UDP, built as the capstone project for SUSTech CS305.

---

## Overview

This repository contains all materials for **SUSTech CS305 Computer Networks**, including lecture slides, lab assignments, exam resources, and the course project -- a **P2P file transfer system with end-to-end reliable data transport** implemented in Python.

The project implements a complete peer-to-peer file sharing protocol with custom reliability mechanisms layered over UDP, supporting multi-peer coordination, congestion control, and error recovery.

Design flow:

```
Socket Programming -> RDT Protocol Design -> P2P Architecture -> Multi-Peer Coordination -> Testing -> Optimization
```

---

## Course Materials

### Lecture Notes

Comprehensive slides covering the full Kurose & Ross (8th Ed.) top-down approach:

| Layer | Topics |
|-------|--------|
| **Application** | HTTP, DNS, FTP, SMTP, Socket programming |
| **Transport** | TCP/UDP, Congestion control, Flow control, RDT |
| **Network** | IP, Routing algorithms (LS, DV), ICMP, IPv6 |
| **Link** | ARP, Ethernet, VLAN, Wireless/Mobile networks |

### Lab Assignments

14 progressive labs covering practical networking skills:

| Lab | Topic |
|-----|-------|
| Lab 1 | Network diagnostic commands (`ping`, `traceroute`, `netstat`) |
| Lab 2-5 | Socket programming, HTTP servers, SMTP/IMAP |
| Lab 6-9 | Transport layer experiments, Wireshark analysis |
| Lab 10-12 | Routing protocols, network configuration |
| Lab 13-14 | Advanced topics & protocol debugging |

---

## Project Architecture

### P2P File Transfer System

The core project implements a **peer-to-peer file transfer protocol** with reliable data transport.

```
+--------------------------------------------------------------------+
|                    P2P File Transfer System                        |
|                                                                    |
|  +----------------+    +------------------+    +----------------+  |
|  |  Tracker       |    |  Peer (Sender)   |    |  Peer (Receiver)|  |
|  |  (Coordination)|<-->|                  |<-->|                  |  |
|  |                |    |  - Chunk manager |    |  - Reassembler  |  |
|  |  - Peer list   |    |  - RDT sender    |    |  - RDT receiver  |  |
|  |  - File registry|    |  - Congestion ctl|    |  - ACK handler   |  |
|  +----------------+    +------------------+    +----------------+  |
|                                                                    |
|  +-------------------------------------------------------------+  |
|  |              Custom RDT Protocol (over UDP)                  |  |
|  |  - Sequence numbers & ACKs        - Retransmission timer     |  |
|  |  - Selective repeat / Go-back-N   - Sliding window           |  |
|  |  - Checksum (corruption detection) - Congestion avoidance    |  |
|  +-------------------------------------------------------------+  |
+--------------------------------------------------------------------+
```

### Module Breakdown

| Module | File / Dir | Responsibility |
|--------|-----------|----------------|
| `tracker/` | `src/tracker/` | Central peer coordination; maintains peer list and file registry |
| `peer/` | `src/peer/` | Peer client; handles file chunking, sending, and receiving |
| `protocol/` | `src/protocol/` | Custom RDT implementation over UDP (ACK, retransmit, flow control) |
| `common/` | `src/common/` | Shared utilities: packet format, checksums, logging |
| `test/` | `test/` | Test suite: topology simulation, loss injection, performance benchmark |
| `example/` | `example/` | Example topologies and configuration files |

### Transport Protocol

Custom Reliable Data Transfer protocol built on UDP:

| Mechanism | Description |
|-----------|-------------|
| **Sequencing** | 32-bit sequence numbers for byte-stream ordering |
| **ACK handling** | Cumulative + selective ACKs with timeout retransmission |
| **Error detection** | Checksum-based corruption detection and discard |
| **Flow control** | Sliding window protocol with dynamic window sizing |
| **Congestion control** | AIMD (Additive Increase Multiplicative Decrease) |

---

## Getting Started

**Requirements:** Python 3.8+

```bash
git clone https://github.com/csgrace/Computer_Networks.git
cd Computer_Networks/project/sustech-cs305-f25-project-starter-main

# Run unit tests
python -m pytest test/

# Start tracker
python -m src.tracker

# Start peer (in another terminal)
python -m src.peer --config example/topology.json
```

---

## Repository

```
Computer_Networks/
|-- lecture/                       # Weekly slides (Kurose & Ross 8th Ed.)
|   |-- assignment/                # Slide-based assignments
|   |-- 笔记/                       # Lecture notes
|-- lab/                           # 14 weekly lab assignments
|   |-- lab1-lab14/                # Lab source and instructions
|   |-- assignment/                # Lab reports and submissions
|-- project/                       # Capstone project (Fall 2025)
|   |-- sustech-cs305-f25-project-starter-main/
|       |-- src/                   # Source code
|       |-- test/                  # Test suite
|       |-- example/               # Example configs and topologies
|       |-- docs/                  # Project documentation
|-- CS305B-2021Spring-Midterm.pdf  # Past midterm reference
|-- 计网期末.pdf                    # Final review materials
|-- computer-networking-a-top-down-approach-8th-edition.pdf  # Textbook
└── README.md
```

---

## Highlights

- **End-to-end RDT protocol**: Built reliable transport from scratch over UDP -- handles packet loss, corruption, reordering, and duplication
- **P2P architecture**: Multi-peer file distribution with tracker-based coordination, supporting parallel chunk downloads
- **Production-grade testing**: Topology simulation with configurable loss rates, latency injection, and bandwidth constraints
- **Congestion control**: Full AIMD implementation with slow-start, congestion avoidance, and fast recovery
- **Incremental complexity**: Progression from basic socket programming (Lab 1) to full P2P system (Project)
