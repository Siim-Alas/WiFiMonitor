using PacketDotNet.Ieee80211;
using System;
using WiFiMonitorClassLibrary.DataTypes;

namespace WiFiMonitorClassLibrary
{
    /// <summary>
    /// Provides methods for parsing PacketDotNet IEEE 802.11 frames.
    /// </summary>
    public static class FrameParser
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
        /// The EAPOL Key Descriptor Type field value indicating an RSN WPA2 key.
        /// </summary>
        private const byte _WPA2EapolKeyDescriptorType = 2;
        /// <summary>
        /// The EAPOL Key Descriptor Type field value indicating an RSN WPA key.
        /// </summary>
        private const byte _WPAEapolKeyDescriptorType = 254;
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