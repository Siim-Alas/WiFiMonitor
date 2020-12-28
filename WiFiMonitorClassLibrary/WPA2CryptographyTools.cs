using PacketDotNet.Ieee80211;
using System;
using System.Text;
using WiFiMonitorClassLibrary.DataTypes;

namespace WiFiMonitorClassLibrary
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
        /// using CCMP decryption. The "numbers only used once" provided needn't 
        /// be in any particular order.
        /// </summary>
        /// <param name="frameToDecrypt">The frame which will get its PayloadData decrypted.</param>
        /// <param name="pairwiseMasterKey">
        /// The pairwise master key (PMK) established between the sender and the destination.
        /// </param>
        /// <param name="nonceA">
        /// A Nonce established between the sender and destination stations during the 4-way 
        /// handshake.
        /// </param>
        /// <param name="nonceB">
        /// The other Nonce established between the sender and destination stations during the 4-way 
        /// handshake.
        /// </param>
        public static void CCMPDecryptDataFrame(
            ref DataFrame frameToDecrypt, 
            byte[] pairwiseMasterKey, 
            byte[] nonceA,
            byte[] nonceB)
        {
            if (frameToDecrypt.FrameControl.Protected == false)
            {
                return;
            }

            byte[] pairwiseTemporalKey = GeneratePairwiseTemporalKey(
                pairwiseMasterKey,
                frameToDecrypt.DestinationAddress.GetAddressBytes(),
                frameToDecrypt.SourceAddress.GetAddressBytes(),
                nonceA,
                nonceB);

            CCMPHeader ccmpHeader = new CCMPHeader(frameToDecrypt);
            // Everything from right after the CCMP header up until the FCS is encrypted
            byte[] encryptedSection = 
                frameToDecrypt.Bytes[(frameToDecrypt.FrameSize + ccmpHeader.Bytes.Length)..^4];

            byte[] nonce = Generate104BitNonce(
                0, frameToDecrypt.SourceAddress.GetAddressBytes(), ccmpHeader.PacketNumber);

            byte[] initialCounter = GenerateCCMPInitialCounter(nonce);

            byte[] decryptedBytes = CryptographyWrapper.AESCounterModeDecryptBytes(
                encryptedSection, pairwiseTemporalKey, initialCounter);

            decryptedBytes.CopyTo(frameToDecrypt.PayloadData, ccmpHeader.Bytes.Length);
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
        /// encrypting the message with AES Counter (CTR) mode).
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
        /// Generates the 512-bit (64-byte) pairwise temporal key (PTK). The provided MAC addresses
        /// and Nonces needn't be in any particular order.
        /// </summary>
        /// <param name="pairwiseMasterKey">The pairwise master key (PMK).</param>
        /// <param name="MACA">The first MAC address.</param>
        /// <param name="MACB">The second MAC address.</param>
        /// <param name="nonceA">The first "number used only once".</param>
        /// <param name="nonceB">The second "number used only once".</param>
        /// <returns>The pairwise temporal key (PTK).</returns>
        private static byte[] GeneratePairwiseTemporalKey(
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
