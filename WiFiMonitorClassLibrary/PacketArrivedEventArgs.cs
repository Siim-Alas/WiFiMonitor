using PacketDotNet;
using System;

namespace WiFiMonitorClassLibrary
{
    public class PacketArrivedEventArgs : EventArgs
    {
        public PacketArrivedEventArgs()
        {
            
        }
        public PacketArrivedEventArgs(Packet arrivedPacket)
        {
            ArrivedPacket = arrivedPacket;
        }

        public Packet ArrivedPacket { get; }
    }
}
