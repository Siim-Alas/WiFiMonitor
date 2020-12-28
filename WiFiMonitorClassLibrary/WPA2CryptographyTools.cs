using PacketDotNet.Ieee80211;
using System;
using System.Linq;
using System.Text;

namespace WiFiMonitorClassLibrary
{
    /// <summary>
    /// Provides methods specific to WPA2 cryptography using CCMP.
    /// </summary>
    public static class WPA2CryptographyTools
    {
        /// <summary>
        /// All IEEE 802.11 Data frames carry an IEEE 802.2 LLC header in the frame body, 
        /// right after the MAC header. This header value indicates an IEEE 802.1X 
        /// Authentication frame.
        /// </summary>
        private readonly static byte[] _IEEE8021XAuthHeader = new byte[] {
            0xAA,             // IEEE 802.2 LLC Header: DSAP = SNAP extension used
            0xAA,             // IEEE 802.2 LLC Header: SSAP = SNAP extension used
            0x03,             // IEEE 802.2 LLC Header: Control = Unnumbered Format PDU
            0x00, 0x00, 0x00, // SNAP Extension: OUI = 0x000000
            0x88, 0x8E        // SNAP Extension: Protocol ID = IEEE 802.1X Authentication
        };
        /// <summary>
        /// The flag (first byte or 8 bits) used in creating the initial RSN CCMP counter.
        /// </summary>
        private readonly static byte _RSNFlag = 0b_0101_1001;
        /// <summary>
        /// The EAPOL Key Descriptor Type field value indicating an RSN WPA2 key.
        /// </summary>
        private readonly static byte _WPA2EapolKeyDescriptorType = 2;
        /// <summary>
        /// The EAPOL Key Descriptor Type field value indicating an RSN WPA key.
        /// </summary>
        private readonly static byte _WPAEapolKeyDescriptorType = 254;
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
        /// <summary>
        /// Tries to extract an EAPOLKeyFormat from the provided PacketDotNet IEEE 802.11 DataFrame.
        /// The body of a data frame carrying EAPOL data is formatted as follows: <br />
        /// 3 bytes (0-2) -- IEEE 802.2 LLC header <br />
        /// 5 bytes (3-7) -- SNAP Extension <br />
        /// 4 bytes (8-11) -- EAPOL MPDU header <br />
        /// n bytes (12-...) -- EAPOL MPDU Body
        /// </summary>
        /// <param name="frame">The frame from which to extract the EAPOLKeyFormat.</param>
        /// <returns>The EAPOLKeyFormat, if it can be extracted. Otherwise, null.</returns>
        public static EAPOLKeyFormat TryGetEAPOLKeyFromDataFrame(DataFrame frame)
        {
            byte[] data = frame.Bytes[frame.FrameSize..^4];

            if (data.Length < 95 + 4 + _IEEE8021XAuthHeader.Length)
            {
                // The data frame body is too short
                Console.WriteLine("too short");
                return null;
            }
            if (HelperMethods.CompareBuffers(
                    _IEEE8021XAuthHeader, data[0.._IEEE8021XAuthHeader.Length]) != 0)
            {
                // The frame is not an IEEE 802.1X Authentication frame (invalid header)
                Console.WriteLine("invalid header");
                return null;
            }
            if (data[_IEEE8021XAuthHeader.Length] != 2)
            {
                // The protocol version in the EAPOL MPDU header is not 2
                Console.WriteLine("invalid protocol version");
                return null;
            }
            if (data[_IEEE8021XAuthHeader.Length + 1] != 3)
            {
                // The EAP Code in the EAPOL MPDU header is not 3 (EAPOL-Key)
                Console.WriteLine("not EAPOL-Key");
                return null;
            }

            byte[] EAPOLBodyLengthField = 
                data[(_IEEE8021XAuthHeader.Length + 2)..(_IEEE8021XAuthHeader.Length + 4)];
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(EAPOLBodyLengthField);
            }
            int EAPOLBodyLength = BitConverter.ToUInt16(EAPOLBodyLengthField);

            if (data.Length < _IEEE8021XAuthHeader.Length + 4 + EAPOLBodyLength)
            {
                // The EAPOL body is too short
                Console.WriteLine("EAPOL body too short");
                return null;
            }

            if ((data[_IEEE8021XAuthHeader.Length + 4] != _WPA2EapolKeyDescriptorType) &&
                (data[_IEEE8021XAuthHeader.Length + 4] != _WPAEapolKeyDescriptorType))
            {
                // The frame is not an RSN WPA2 or WPA key frame (invalid Descriptor Type field)
                Console.WriteLine("invalid Descryptor Type field");
                return null;
            }

            EAPOLKeyFormat keyFormat = 
                new EAPOLKeyFormat(data[(_IEEE8021XAuthHeader.Length + 4)..]);

            if (keyFormat.KeyData.Length != keyFormat.KeyDataLength)
            {
                // The KeyDataLength field is invalid
                Console.WriteLine("invalid keydata length");
                return null;
            }

            return keyFormat;
        }
    }
}
