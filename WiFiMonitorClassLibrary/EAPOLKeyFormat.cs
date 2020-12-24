using System;

namespace WiFiMonitorClassLibrary
{
    public class EAPOLKeyFormat
    {
        public EAPOLKeyFormat(byte[] rawBytes)
        {
            Bytes = rawBytes;
            
            if (KeyData.Length != KeyDataLength)
            {
                throw new ArgumentException("The provided rawBytes are in incorrect format.");
            }

            KeyInformation = new EAPOLKeyInformationField(rawBytes[1..3]);
        }
        public byte[] Bytes;
        public int DescryptorType
        {
            get { return Bytes[0]; }
        }
        public EAPOLKeyInformationField KeyInformation;
        public uint KeyLength
        {
            get 
            { 
                byte[] kl = Bytes[3..5];
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(kl);
                }
                return BitConverter.ToUInt16(kl); 
            }
        }
        public ulong ReplayCounter
        {
            get 
            { 
                byte[] rc = Bytes[5..13];
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(rc);
                }
                return BitConverter.ToUInt64(rc); 
            }
        }
        public byte[] KeyNonce
        {
            get { return Bytes[13..45]; }
        }
        public byte[] EAPOLKeyIV
        {
            get { return Bytes[45..51]; }
        }
        public byte[] KeyReceiveSequenceCounter
        {
            get { return Bytes[51..59]; }
        }
        public byte[] KeyIdentifier
        {
            get { return Bytes[59..67]; }
        }
        public byte[] KeyMIC
        {
            get { return Bytes[67..83]; }
        }
        public uint KeyDataLength
        {
            get 
            { 
                byte[] kdl = Bytes[83..85];
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(kdl);
                }
                return BitConverter.ToUInt16(kdl); 
            }
        }
        public byte[] KeyData
        {
            get { return (Bytes.Length > 85) ? Bytes[85..] : new byte[0]; }
        }
    }
}
