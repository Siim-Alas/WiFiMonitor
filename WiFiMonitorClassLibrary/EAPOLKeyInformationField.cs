using System;

namespace WiFiMonitorClassLibrary
{
    public readonly struct EAPOLKeyInformationField
    {
        public EAPOLKeyInformationField(byte[] rawBytes)
        {
            if (rawBytes.Length != 2)
            {
                throw new ArgumentException("The byte array provided was not of length 2.");
            }
            Bytes = rawBytes;
        }
        public readonly byte[] Bytes;
        public bool Request
        {
            get { return (Bytes[0] & 0b_0001_0000) != 0; }
        }
        public bool Error 
        {
            get { return (Bytes[0] & 0b_0010_000) != 0; }
        }
        public bool Secure 
        {
            get { return (Bytes[0] & 0b_0100_000) != 0; }
        }
        public bool MICBit 
        {
            get { return (Bytes[0] & 0b_1000_000) != 0; }
        }
        public bool AckBit 
        {
            get { return (Bytes[1] & 0b_0000_0001) != 0; }
        }
        public bool KeyUsage 
        {
            get { return (Bytes[1] & 0b_0000_0010) != 0; }
        }
        public int KeyIndex 
        {
            get { return (Bytes[1] & 0b_0000_1100) >> 2; }
        }
        public bool KeyType 
        {
            get { return (Bytes[1] & 0b_0001_0000) != 0; }
        }
        public int KeyDescriptorTypeNumber
        {
            get { return (Bytes[1] & 0b_1110_0000) >> 5; }
        }
    }
}