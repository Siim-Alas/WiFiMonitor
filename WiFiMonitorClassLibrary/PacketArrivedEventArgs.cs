using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Text;

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
