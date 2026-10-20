# CodeAlpha Basic Network Sniffer

## Project Overview
A Python-based network sniffer developed
as part of the CodeAlpha Cyber Security Internship.

## Features
- Capture IP network packets
- Identify TCP, UDP and ICMP protocols
- Display source and destination IP addresses
- Record packet timestamps
- Display packet sizes
- Export packet metadata to CSV
- Maintain application logs
- Display a capture summary

## Technologies Used
- Python 3.13
- Scapy
- Npcap
- CSV
- Python Logging

## Requirements
- Windows 10/11
- Python 3.13
- Scapy
- Npcap

## Installation

Install Scapy:

    python -m pip install scapy

Install Npcap from its official website.

## Usage

Run the program:

    python network_sniffer.py

The program captures up to 20 IP packets
and saves packet metadata and logs in the
reports directory.

## Output
- CSV packet report
- Application log file
- Terminal capture summary

## Ethical Use
Use this tool only on your own computer
or networks you are authorized to monitor.

This project records packet metadata and
does not decrypt encrypted application traffic.

## Internship
CodeAlpha Cyber Security Internship