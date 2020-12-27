
namespace WiFiMonitorClassLibrary
{
    /// <summary>
    /// A struct that wraps a byte array and simplifies reading the EAPOL Key Information field.
    /// </summary>
    public readonly struct EAPOLKeyInformationField
    {
        /// <summary>
        /// The constructor. Note that no error checking is performed in this operation.
        /// </summary>
        /// <param name="rawBytes">A length 2 byte array holding the Key Information field.</param>
        public EAPOLKeyInformationField(byte[] rawBytes)
        {
            Bytes = rawBytes;
        }
        public readonly byte[] Bytes;
        /// <summary>
        /// Set to 1 by the supplicant (STA) to request the authenticator (AP) initiate a new 
        /// 4-way handshake, otherwise 0.
        /// </summary>
        public bool Request
        {
            get { return (Bytes[0] & 0b_0001_0000) != 0; }
        }
        /// <summary>
        /// Set to 1 by a party when it detected some error in the message received, otherwise
        /// 0.
        /// </summary>
        public bool Error 
        {
            get { return (Bytes[0] & 0b_0010_000) != 0; }
        }
        /// <summary>
        /// Set to 1 when the 4-way handshake completes to indicate that further communications 
        /// will be secure (data encrypted), otherwise 0.
        /// </summary>
        public bool Secure 
        {
            get { return (Bytes[0] & 0b_0100_000) != 0; }
        }
        /// <summary>
        /// Set to 1 if a MIC has been computed and inserted into the MIC field of the EAPOL-Key
        /// data frame, otherwise 0.
        /// </summary>
        public bool MICBit 
        {
            get { return (Bytes[0] & 0b_1000_000) != 0; }
        }
        /// <summary>
        /// Set to 1 by the authenticator (AP) if it expects a response from the supplicant (STA),
        /// otherwise 0.
        /// </summary>
        public bool AckBit 
        {
            get { return (Bytes[1] & 0b_0000_0001) != 0; }
        }
        /// <summary>
        /// Set to 1 if a new pairwise key should be installed, otherwise 0.
        /// </summary>
        public bool KeyUsage 
        {
            get { return (Bytes[1] & 0b_0000_0010) != 0; }
        }
        /// <summary>
        /// Indicates key index for group keys.
        /// </summary>
        public int KeyIndex 
        {
            get { return (Bytes[1] & 0b_0000_1100) >> 2; }
        }
        /// <summary>
        /// Set to 1 for pairwise and to 0 for group keys.
        /// </summary>
        public bool KeyType 
        {
            get { return (Bytes[1] & 0b_0001_0000) != 0; }
        }
        /// <summary>
        /// A number indicating the version and scheme of authentication used.
        /// </summary>
        public int KeyDescriptorTypeNumber
        {
            get { return (Bytes[1] & 0b_1110_0000) >> 5; }
        }
    }
}