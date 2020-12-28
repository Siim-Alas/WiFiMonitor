using PacketDotNet;
using System;

namespace WiFiMonitorClassLibrary.DataTypes
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
