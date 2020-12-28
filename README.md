
# WiFi Monitor

WiFi Monitor is a simple application for a school project. It listens for, captures, 
and displays various internet packets.

## Disclaymer

Some capabilities of WiFi Monitor ***CAN ONLY BE USED FOR ACADEMIC PURPOSES!!!***
Before use, one should familiarize themselves with the appliccable laws and regulations in 
their country.

## Dependencies

This library utilizes the [SharpPcap](https://github.com/chmorgan/sharppcap) library via
its respective [NuGet package](https://www.nuget.org/packages/SharpPcap/). The aforementioned 
library, and thus also this library, requires the end-user to install the following API-s.

* [Libpcap](http://www.tcpdump.org/manpages/pcap.3pcap.html) for Linux users
* [Npcap](https://nmap.org/npcap/) for Windows users

The respective libraries would be included here if it were not for copyright concerns.

## Running With Sudo on Unix

Running the ConsoleUI with sudo on Unix devices (tested on Ubuntu 
20.04 LTS) requires the following.

* Building the ConsoleUI as usual.
* Running ConsoleUI with the command `sudo dotnet run --no-build --project <pathToConsoleUI>`
as per the [docs](https://docs.microsoft.com/en-us/dotnet/core/tools/elevated-access).