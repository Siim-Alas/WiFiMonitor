using PacketDotNet.Ieee80211;
using System;

namespace WiFiMonitorClassLibrary.Parsing
{
    /// <summary>
    /// A byte array wrapper which simplifies reading CCMP header fields.
    /// </summary>
    public readonly struct CCMPHeader
    {
        /// <summary>
        /// Constructs a new CCMP header from the bytes of a PacketDonNet IEEE 802.11 MacFrame.
        /// </summary>
        public CCMPHeader(MacFrame frame)
        {
            // The CCMP header is the first 8 (unencrypted) bytes following the MAC header of the frame.
            Bytes = new byte[8];
            Array.Copy(frame.Bytes, frame.FrameSize, Bytes, 0, Bytes.Length);
        }
        public readonly byte[] Bytes;
        /// <summary>
        /// The 6-byte packet number makes up the first 2 as well as the last 4 bytes of the
        /// CCMP header. It is used in constructing the "number used only once" (Nonce) used
        /// both in MIC computation and data encryption with AES Counter (CTR) mode. <br />
        /// Note that this getter reverses the packet number array contained in the CCMP
        /// header. The packet number field in the CCMP header is little-endian, but this
        /// implementation makes it big-endian.
        /// </summary>
        public byte[] PacketNumber
        {
            get 
            {
                byte[] packetNumber = new byte[6]
                {
                    Bytes[7],
                    Bytes[6],
                    Bytes[5],
                    Bytes[4],

                    Bytes[1],
                    Bytes[0]
                };
                return packetNumber;
            }
        }
        /// <summary>
        /// The 2-bit Key Identifier is the last 2 bits of byte 3 (zero based) of the CCMP header.
        /// </summary>
        public byte KeyID
        {
            get { return (byte)(Bytes[3] >> 6); }
        }
    }
}
