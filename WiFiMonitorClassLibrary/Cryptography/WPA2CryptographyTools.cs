using PacketDotNet.Ieee80211;
using System;
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
        /// <summary>
        /// The flag (first byte or 8 bits) used in creating the initial RSN CCMP counter.
        /// </summary>
        private readonly static byte _RSNFlag = 0b_0101_1001;
        /// <summary>
        /// Decrypts a PacketDotNet IEEE 802.11 DataFrame (containing one MPDU)
        /// using CCMP decryption.
        /// </summary>
        /// <param name="frameToDecrypt">The data frame containing the data to decrypt.</param>
        /// <param name="pairwiseTemporalKey">
        /// The Pairwise Taster Key (PTK) established between the sender and the destination.
        /// </param>
        /// <returns>
        /// The decrypted data from the body of the frame provided. Note that this includes
        /// both the original data of the frame and the 64-bit (8-byte) MIC appended to it.
        /// </returns>
        public static byte[] CCMPDecryptDataFrame(
            DataFrame frameToDecrypt, 
            byte[] pairwiseTemporalKey)
        {
            if (frameToDecrypt.FrameControl.Protected == false)
            {
                return frameToDecrypt.PayloadData;
            }

            /*
            byte[] pairwiseTemporalKey = GeneratePairwiseTemporalKey(
                pairwiseMasterKey,
                frameToDecrypt.DestinationAddress.GetAddressBytes(),
                frameToDecrypt.SourceAddress.GetAddressBytes(),
                nonceA,
                nonceB);
            */

            CCMPHeader ccmpHeader = new CCMPHeader(frameToDecrypt);
            // Everything from right after the CCMP header up until the FCS is encrypted
            byte[] encryptedSection = 
                frameToDecrypt.Bytes[(frameToDecrypt.FrameSize + ccmpHeader.Bytes.Length)..^4];

            byte[] nonce = Generate104BitNonce(
                0, frameToDecrypt.SourceAddress.GetAddressBytes(), ccmpHeader.PacketNumber);

            byte[] initialCounter = GenerateCCMPInitialCounter(nonce);

            byte[] decryptedBytes = CryptographyWrapper.AESCounterModeDecryptBytes(
                encryptedSection, pairwiseTemporalKey, initialCounter);

            // decryptedBytes.CopyTo(frameToDecrypt.PayloadData, ccmpHeader.Bytes.Length);
            return decryptedBytes;
        }
        /// <summary>
        /// Generates the 104-bit (13-byte) "number used only once" used in the CCMP encryption 
        /// of both the frame MPDU data and MIC section.
        /// </summary>
        /// <param name="priority">
        /// The priority of the packet, potentially different for various transmitted data types.
        /// </param>
        /// <param name="sourceMACAddress">The MAC address of the source of the frame.</param>
        /// <param name="packetNumber">The packet number of the frame</param>
        /// <returns>The Nonce.</returns>
        private static byte[] Generate104BitNonce(
            byte priority, 
            byte[] sourceMACAddress, 
            byte[] packetNumber)
        {
            byte[] nonce = new byte[104 / 8];
            nonce[0] = priority;
            sourceMACAddress.CopyTo(nonce, 1);
            packetNumber.CopyTo(nonce, 7); // Priority length (1 byte) + MAC address length (6 bytes)
            return nonce;
        }
        /// <summary>
        /// Generates the value of the initial CCMP counter (the first 128-bit block CCMP uses in 
        /// encrypting the message with AES Counter (CTR) mode). The initial counter is composed
        /// as follows: <br />
        /// 1 byte (0) -- RSN flag <br />
        /// 13 bytes (1-13) -- 104-bit Nonce <br />
        /// 2 bytes (14-16) -- 1 as a 16-bit unsigned integer (this gets incremented on subsequent
        /// iterations)
        /// </summary>
        /// <param name="nonce">
        /// The 104-bit (13-byte) "number used only once" used in creating the initial counter.
        /// </param>
        /// <returns>The 128-bit (16-byte) CCMP initial counter.</returns>
        private static byte[] GenerateCCMPInitialCounter(byte[] nonce)
        {
            byte[] ctr = BitConverter.GetBytes((ushort)1); // 1 as an unsigned 16-bit (2-byte) integer

            byte[] counter = new byte[128 / 8];
            counter[0] = _RSNFlag;
            nonce.CopyTo(counter, 1);
            ctr.CopyTo(counter, counter.Length - 3);

            return counter;
        }
        /// <summary>
        /// Generates the Pairwise Master Key (PMK) for an Access Point (AP). In WPA2, the
        /// PMK is used for calculating the Pairwise Temporal Key (PTK), which is the actual
        /// key used for encrypting the frames.
        /// </summary>
        /// <param name="accessPointBSSID">The BSSID of the AP.</param>
        /// <param name="accessPointPassword">The password of the AP.</param>
        /// <returns>The PMK.</returns>
        public static byte[] GeneratePairwiseMasterKey(
            byte[] accessPointBSSID,
            string accessPointPassword)
        {
            byte[] pairwiseMasterKey = 
                CryptographyWrapper.PBKDF2(accessPointPassword, accessPointBSSID, 4096, 32);

            return pairwiseMasterKey;
        }
        /// <summary>
        /// Generates the 512-bit (64-byte) Pairwise Temporal Key (PTK). The provided MAC addresses
        /// and "numbers used only once" (Nonces) needn't be in any particular order, since
        /// the PTK is calculated as follows: <br />
        /// PTK = PRF-512(PMK, min(MACA, MACB) | max(MACA, MACB) | min(NonceA, NonceB) | 
        /// max(nonceA, NonceB)) <br />
        /// where "|" signifies byte array concatenation.
        /// </summary>
        /// <param name="pairwiseMasterKey">The Pairwise Master Key (PMK).</param>
        /// <param name="MACA">The first MAC address.</param>
        /// <param name="MACB">The second MAC address.</param>
        /// <param name="nonceA">The first Nonce.</param>
        /// <param name="nonceB">The second Nonce.</param>
        /// <returns>The PTK.</returns>
        public static byte[] GeneratePairwiseTemporalKey(
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

            byte[] specificData = new byte[MAC1.Length + MAC2.Length + nonce1.Length + nonce2.Length];
            MAC1.CopyTo(specificData, 0);
            MAC2.CopyTo(specificData, MAC1.Length);
            nonce1.CopyTo(specificData, MAC1.Length + MAC2.Length);
            nonce2.CopyTo(specificData, MAC1.Length + MAC2.Length + nonce1.Length);

            byte[] temporalKey = CryptographyWrapper.PRFn(
                CryptographyWrapper.PRFBitValues.bit512,
                pairwiseMasterKey,
                Encoding.UTF8.GetBytes("Pairwise key expansion"), 
                specificData);

            return temporalKey;
        }
    }
}
