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
        /// The Key Information field expected on message number 1 of the 4-way handshake.
        /// </summary>
        private readonly static EAPOLKeyInformationField _keyInfoFieldOn4WHSMessage1 = 
            new EAPOLKeyInformationField(
                request: false,
                error: false,
                secure: false,
                mic: false,
                ack: true,
                install: false,
                keyIndex: 0b_00,
                keyType: true,
                keyDescriptorNumber: 0b_010
        );
        /// <summary>
        /// The Key Information field expected on message number 2 of the 4-way handshake.
        /// </summary>
        private readonly static EAPOLKeyInformationField _keyInfoFieldOn4WHSMessage2 = 
            new EAPOLKeyInformationField(
            request: false,
            error: false,
            secure: false,
            mic: true,
            ack: false,
            install: false,
            keyIndex: 0b_00,
            keyType: true,
            keyDescriptorNumber: 0b_010
        );
        /// <summary>
        /// The Key Information field expected on message number 3 of the 4-way handshake.
        /// </summary>
        private readonly static EAPOLKeyInformationField _keyInfoFieldOn4WHSMessage3 = 
            new EAPOLKeyInformationField(
            request: false,
            error: false,
            secure: false,
            mic: true,
            ack: true,
            install: false,
            keyIndex: 0b_00,
            keyType: true,
            keyDescriptorNumber: 0b_010
        );
        /// <summary>
        /// The Key Information field expected on message number 4 of the 4-way handshake.
        /// </summary>
        private readonly static EAPOLKeyInformationField _keyInfoFieldOn4WHSMessage4 = 
            new EAPOLKeyInformationField(
            request: false,
            error: false,
            secure: false,
            mic: true,
            ack: false,
            install: true,
            keyIndex: 0b_00,
            keyType: true,
            keyDescriptorNumber: 0b_010
        );
        /// <summary>
        /// All IEEE 802.11 Data frames carry an IEEE 802.2 LLC header in the frame body, 
        /// right after the MAC header. This header value indicates an IEEE 802.1X 
        /// Authentication frame.
        /// </summary>
        private readonly static byte[] _IEEE8021XAuthHeader = new byte[] 
        {
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
        /// Tries to extract the EAPOL-Key message data from the provided PacketDotNet IEEE 802.11 
        /// DataFrame. The body of a data frame carrying EAPOL data is formatted as follows: <br />
        /// 3 bytes (0-2) -- IEEE 802.2 LLC header <br />
        /// 5 bytes (3-7) -- SNAP Extension <br />
        /// 4 bytes (8-11) -- EAPOL MPDU header <br />
        /// n bytes (12-...) -- EAPOL MPDU Body (in this case, the EAPOLKeyFormat)
        /// </summary>
        /// <param name="frame">The frame from which to extract the EAPOLKeyFormat.</param>
        /// <returns>The EAPOL-Key message data, if it can be extracted. Otherwise, null.</returns>
        private static EAPOLKeyFormat TryToGetEAPOLKeyFromDataFrame(DataFrame frame)
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

            EAPOLKeyFormat keyFormat = new EAPOLKeyFormat(data[(_IEEE8021XAuthHeader.Length + 4)..]);

            if (keyFormat.KeyData.Length != keyFormat.KeyDataLength)
            {
                // The KeyDataLength field is invalid
                Console.WriteLine("invalid keydata length");
                return null;
            }

            return keyFormat;
        }
        /// <summary>
        /// Tries to parse the given frame as if it were a message in the 4-way handshake.
        /// </summary>
        /// <param name="frame">The frame to parse.</param>
        /// <param name="keyFormat">
        /// The EAPOL-Key message data, if it has successfully been parsed. Otherwise, null.
        /// </param>
        /// <returns>
        /// The number of the message in the 4-way handshake (either 1, 2, 3, or 4), if it can
        /// be parsed. Otherwise, -1.
        /// </returns>
        public static int TryToParse4WayHandshake(
            DataFrame frame, 
            out EAPOLKeyFormat keyFormat)
        {
            keyFormat = TryToGetEAPOLKeyFromDataFrame(frame);
            if (keyFormat == null)
            {
                // The frame didn't pass the filters
                return -1;
            }

            if (keyFormat.KeyInformation == _keyInfoFieldOn4WHSMessage1)
            {
                return 1;
            }
            if (keyFormat.KeyInformation == _keyInfoFieldOn4WHSMessage2)
            {
                return 2;
            }
            if (keyFormat.KeyInformation == _keyInfoFieldOn4WHSMessage3)
            {
                return 3;
            }
            if (keyFormat.KeyInformation == _keyInfoFieldOn4WHSMessage4)
            {
                return 4;
            }

            return -1;
        }
    }
}