using PacketDotNet.Ieee80211;
using System.Text;
using WiFiMonitorClassLibrary.Parsing;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibrary.Cryptography
{
    /// <summary>
    /// Provides methods specific to WPA2 cryptography using CCMP.
    /// </summary>
    public static class WPA2CryptographyTools
    {
        private readonly static byte[] _pairwiseKeyExpansionText = 
            Encoding.ASCII.GetBytes("Pairwise key expansion");
        /// <summary>
        /// Tries to decrypt a PacketDotNet IEEE 802.11 DataFrame (containing one MPDU)
        /// using CCMP decryption.
        /// </summary>
        /// <param name="dataFrame">The data frame containing the data to decrypt.</param>
        /// <param name="temporalKey">
        /// The 128-bit (16-byte) Temporal Key (TK) used in data encryption. This is the 3-rd
        /// key contained in the Pairwise Transient Key (PTK) instated between the sender
        /// and recipient of this frame.
        /// </param>
        /// <returns>
        /// The decrypted data from the body of the frame provided, if it can be decrypted. 
        /// Otherwies, null. Note that this includes both the original data of the frame and 
        /// the 64-bit (8-byte) MIC appended to it.
        /// </returns>
        public static byte[] CCMPTryDecryptDataFrame(
            DataFrame dataFrame, 
            byte[] temporalKey)
        {
            if (dataFrame?.PayloadData == null)
            {
                // The frame or its PayloadData was null
                return null;
            }
            if (temporalKey == null)
            {
                // The temporal key was null
                return null;
            }
            if (temporalKey.Length != 16)
            {
                // The temporal key was not 128 bits or 16 bytes long
                return null;
            }
            if (dataFrame.FrameControl.Protected == false)
            {
                return dataFrame.PayloadData;
            }

            byte priority;
            if (dataFrame is QosDataFrame qosDataFrame)
            {
                // Get the first 4-bit subfield (Traffic Identifier) of the QoS Control field
                // in the IEEE 802.11 MAC header
                priority = (byte)(qosDataFrame.QosControl & 0b_0000_0000_0000_1111);
            }
            else 
            {
                priority = 0;
            }

            CCMPHeader ccmpHeader = new CCMPHeader(dataFrame);

            // Everything from right after the CCMP header up until the FCS is encrypted
            byte[] originalDataAndMIC = dataFrame.AppendFcs ?
                dataFrame.Bytes[(dataFrame.FrameSize + 8)..^4] :
                dataFrame.Bytes[(dataFrame.FrameSize + 8)..];

            byte[] nonce = Generate104BitNonce(
                priority, 
                dataFrame.SourceAddress.GetAddressBytes(), 
                ccmpHeader.PacketNumber);

            byte[] tag = new byte[8];

            // With the AES CCM mode, encryption and decryption are identical
            CryptographyWrapper.AESCCMEncryptBytes(
                originalDataAndMIC, nonce, temporalKey, tag);
            return originalDataAndMIC;
        }
        /// <summary>
        /// Generates the 104-bit (13-byte) "number used only once" used in the CCMP encryption 
        /// of both the frame MPDU data and MIC section.
        /// </summary>
        /// <param name="priority">
        /// The priority of the packet, potentially different for various transmitted data types.
        /// </param>
        /// <param name="sourceMACAddress">The MAC address of the source of the frame.</param>
        /// <param name="packetNumber">The packet number of the frame.</param>
        /// <returns>The Nonce.</returns>
        private static byte[] Generate104BitNonce(
            byte priority, 
            byte[] sourceMACAddress, 
            byte[] packetNumber)
        {
            byte[] nonce = new byte[104 / 8];
            nonce[0] = priority;
            sourceMACAddress.CopyTo(nonce, 1);
            packetNumber.CopyTo(nonce, 1 + 6); // Priority length + MAC address length
            return nonce;
        }
        /// <summary>
        /// Generates the Pairwise Master Key (PMK) for an Access Point (AP). In WPA2, the
        /// PMK is used for calculating the Pairwise Temporal Key (PTK), which is the actual
        /// key used for encrypting the frames.
        /// </summary>
        /// <param name="password">The password of the AP.</param>
        /// <param name="ssid">The SSID of the AP.</param>
        /// <returns>The PMK.</returns>
        public static byte[] GeneratePairwiseMasterKey(
            string password,
            string ssid)
        {
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] saltBytes = Encoding.ASCII.GetBytes(ssid);

            byte[] pairwiseMasterKey = CryptographyWrapper.PBKDF2(
                passwordBytes, 
                saltBytes, 
                4096, 
                32);

            return pairwiseMasterKey;
        }
        /// <summary>
        /// Generates the 384-bit (48-byte) Pairwise Transient Key (PTK) for CCMP. The 
        /// provided MAC addresses and "numbers used only once" (Nonces) needn't be in 
        /// any particular order, since the PTK is calculated as follows: <br />
        /// PTK = PRF-384(PMK, min(MACA, MACB) | max(MACA, MACB) | min(NonceA, NonceB) | 
        /// max(nonceA, NonceB)) <br />
        /// where "|" signifies byte array concatenation.
        /// </summary>
        /// <param name="pairwiseMasterKey">The Pairwise Master Key (PMK).</param>
        /// <param name="MACA">The first MAC address.</param>
        /// <param name="MACB">The second MAC address.</param>
        /// <param name="nonceA">The first Nonce.</param>
        /// <param name="nonceB">The second Nonce.</param>
        /// <returns>The PTK.</returns>
        public static byte[] GeneratePairwiseTransientKey(
            byte[] pairwiseMasterKey, 
            byte[] MACA, 
            byte[] MACB,
            byte[] nonceA,
            byte[] nonceB)
        {
            // MAC1 has to be numerically less than MAC2.
            HelperMethods.CompareBuffers(MACA, MACB, out byte[] MAC1, out byte[] MAC2);
            // Nonce1 has to be numerically less than nonce2.
            HelperMethods.CompareBuffers(nonceA, nonceB, out byte[] nonce1, out byte[] nonce2);

            // The MAC addresses are 6 bytes long and the Nonces are 32 bytes long
            byte[] specificData = new byte[6 + 6 + 32 + 32];
            MAC1.CopyTo(specificData, 0);
            MAC2.CopyTo(specificData, 6);
            nonce1.CopyTo(specificData, 6 + 6);
            nonce2.CopyTo(specificData, 6 + 6 + 32);

            byte[] pairwiseTransientKey = CryptographyWrapper.PRFn(
                CryptographyWrapper.PRFBitValues.bit384,
                pairwiseMasterKey,
                _pairwiseKeyExpansionText, 
                specificData);

            return pairwiseTransientKey;
        }
    }
}
