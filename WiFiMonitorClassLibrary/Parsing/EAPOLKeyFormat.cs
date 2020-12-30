using System;

namespace WiFiMonitorClassLibrary.Parsing
{
    /// <summary>
    /// A byte array wrapper which simplifies accessing WPA2 EAPOL-Key data fields.
    /// </summary>
    public class EAPOLKeyFormat
    {
        /// <summary>
        /// Instantiates the class. Note that no error checking is performed in this
        /// operation.
        /// </summary>
        /// <param name="rawBytes">The byte array containing the EAPOL-Key data fields.</param>
        public EAPOLKeyFormat(byte[] rawBytes)
        {
            Bytes = rawBytes;
            KeyInformation = new EAPOLKeyInformationField(rawBytes[1..3]);
        }
        /// <summary>
        /// The byte array from which all the fields are read.
        /// </summary>
        public readonly byte[] Bytes;
        /// <summary>
        /// The Descryptor Type field, indicates the type of key.
        /// </summary>
        public int DescryptorType
        {
            get { return Bytes[0]; }
        }
        /// <summary>
        /// The Key Information field, holds information about the key as well as control data.
        /// </summary>
        public readonly EAPOLKeyInformationField KeyInformation;
        /// <summary>
        /// The Key Length field, indicates the length of the key.
        /// </summary>
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
        /// <summary>
        /// The Replay Counter field, used to prevent replay attacks and double proccessing.
        /// </summary>
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
        /// <summary>
        /// The Nonce value used to derive the key.
        /// </summary>
        public byte[] KeyNonce
        {
            get { return Bytes[13..45]; }
        }
        /// <summary>
        /// The EAPOL Key IV (Initialization Vector) field, used in Group Key Transfer
        /// to indicate which IV has been used in the EAPOL-Key encryption of the 
        /// Group Transfer Key (GTK) held in the Key Data field of this message.
        /// </summary>
        public byte[] EAPOLKeyIV
        {
            get { return Bytes[45..61]; }
        }
        /// <summary>
        /// The Key Receive Sequence Counter (RSC) field, indicates the sequence number
        /// of the first message after the keys are installed. Used to prevent replay
        /// attacks.
        /// </summary>
        public byte[] KeyReceiveSequenceCounter
        {
            get { return Bytes[61..69]; }
        }
        /// <summary>
        /// The Key Identifier field.
        /// </summary>
        public byte[] KeyIdentifier
        {
            get { return Bytes[69..77]; }
        }
        /// <summary>
        /// The Key MIC field, used to ensure the integrity of the message.
        /// </summary>
        public byte[] KeyMIC
        {
            get { return Bytes[77..93]; }
        }
        /// <summary>
        /// The Key Data Length field, indicates the length of the Key Data field.
        /// </summary>
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
        /// <summary>
        /// The Key Data field, may hold pertinent data (depending on the message).
        /// </summary>
        public byte[] KeyData
        {
            get { return Bytes[95..]; }
        }
        /// <summary>
        /// A check to see if the Bytes provided is long enough to have a valid message
        /// and to see if the Key Data Length field correctly describes the length of 
        /// the Key Data field.
        /// </summary>
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
