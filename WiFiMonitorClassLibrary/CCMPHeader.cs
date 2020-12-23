using PacketDotNet.Ieee80211;
using System;

namespace WiFiMonitorClassLibrary
{
    public readonly struct CCMPHeader
    {
        public CCMPHeader(MacFrame frame)
        {
            // The CCMP header is the first 8 (unencrypted) bytes following the MAC header of the frame.
            Bytes = new byte[8];
            Array.Copy(frame.Bytes, frame.FrameSize, Bytes, 0, Bytes.Length);

            // The 6-byte packet number makes up the first two as well as the last four bytes of the CCMP header.
            PacketNumber = new byte[6];
            Array.Copy(Bytes, 0, PacketNumber, 0, 2);
            Array.Copy(Bytes, 4, PacketNumber, 2, 4);

            // The 2 key ID bits are the last two bits of the 4-th byte (index 3) of the CCMP header.
            KeyID = (byte)(Bytes[3] & 0b_0000_0011); // C# binary notation
        }
        public readonly byte[] Bytes;
        public readonly byte[] PacketNumber;
        public readonly byte KeyID;
    }
}
