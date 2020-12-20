
# WiFi Monitor

WiFi Monitor is a simple application for a school project.
It listens for, captures, and displays various internet packets.

## Running With Sudo on Unix
Running the ConsoleUI with sudo on Unix devices (tested on Ubuntu 
20.04 LTS) requires the following.

* Building the ConsoleUI as usual.
* Running ConsoleUI with the command `sudo dotnet run --no-build --project <pathToConsoleUI>`
as per the [docs](https://docs.microsoft.com/en-us/dotnet/core/tools/elevated-access).