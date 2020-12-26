using System;

namespace WiFiMonitorClassLibrary
{
    public class EAPOLKeyFormat
    {
        public EAPOLKeyFormat(byte[] rawBytes)
        {
            Bytes = rawBytes;
            KeyInformation = new EAPOLKeyInformationField(rawBytes[1..3]);
        }
        public readonly byte[] Bytes;
        public int DescryptorType
        {
            get { return Bytes[0]; }
        }
        public readonly EAPOLKeyInformationField KeyInformation;
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
            get { return Bytes[45..61]; }
        }
        public byte[] KeyReceiveSequenceCounter
        {
            get { return Bytes[61..69]; }
        }
        public byte[] KeyIdentifier
        {
            get { return Bytes[69..77]; }
        }
        public byte[] KeyMIC
        {
            get { return Bytes[77..93]; }
        }
        public uint KeyDataLength
        {
            get 
            { 
                byte[] kdl = Bytes[93..95];
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(kdl);
                }
                return BitConverter.ToUInt16(kdl); 
            }
        }
        public byte[] KeyData
        {
            get { return Bytes[95..]; }
        }
        public bool IsValid
        {
            get 
            {
                if (Bytes.Length < 95)
                {
                    return false;
                }
                if (KeyData.Length != KeyDataLength)
                {
                    return false;
                }
                return true;
            }
        }
    }
}
