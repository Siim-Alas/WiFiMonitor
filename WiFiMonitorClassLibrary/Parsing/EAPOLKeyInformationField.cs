using System;
using System.Collections;
using System.Collections.Generic;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibrary.Parsing
{
    /// <summary>
    /// A class that wraps a byte array and simplifies reading the EAPOL Key Information field.
    /// </summary>
    public class EAPOLKeyInformationField : IEquatable<EAPOLKeyInformationField>
    {
        /// <summary>
        /// Constructs a new instance from the rawBytes. Note that no error checking is performed 
        /// in this operation.
        /// </summary>
        /// <param name="rawBytes">A length 2 byte array holding the Key Information field.</param>
        public EAPOLKeyInformationField(byte[] rawBytes)
        {
            Bytes = rawBytes;
        }
        /// <summary>
        /// Constructs a new instance from the arguments given. Note that no error checking is 
        /// performed in this operation.
        /// </summary>
        /// <param name="request">
        /// Set to 1 by the supplicant (STA) to request the authenticator (AP) initiate a new 
        /// 4-way handshake, otherwise 0.
        /// </param>
        /// <param name="error">
        /// Set to 1 by a party when it detected some error in the message received, otherwise 0.
        /// </param>
        /// <param name="secure">
        /// Set to 1 when the 4-way handshake completes to indicate that further communications 
        /// will be secure (data encrypted), otherwise 0.
        /// </param>
        /// <param name="mic">
        /// Set to 1 if a MIC has been computed and inserted into the MIC field of the EAPOL-Key
        /// data frame, otherwise 0.
        /// </param>
        /// <param name="ack">
        /// Set to 1 by the authenticator (AP) if it expects a response from the supplicant (STA),
        /// otherwise 0.
        /// </param>
        /// <param name="install">
        /// Set to 1 if a new pairwise key should be installed, otherwise 0.
        /// </param>
        /// <param name="keyIndex">
        /// 2 bits, indicates key index for group keys.
        /// </param>
        /// <param name="keyType">
        /// Set to 1 for pairwise and to 0 for group keys.
        /// </param>
        /// <param name="keyDescriptorNumber">
        /// 3 bits, a number indicating the version and scheme of authentication used.
        /// </param>
        public EAPOLKeyInformationField(
            bool request,
            bool error,
            bool secure,
            bool mic,
            bool ack,
            bool install,
            byte keyIndex,
            bool keyType,
            byte keyDescriptorNumber)
        {
            Bytes = new byte[2];
            
            if (request)
            {
                Bytes[0] |= 0b_0000_1000;
            }
            if (error)
            {
                Bytes[0] |= 0b_0000_0100;
            }
            if (secure)
            {
                Bytes[0] |= 0b_0000_0010;
            }
            if (mic)
            {
                Bytes[0] |= 0b_0000_0001;
            }
            if (ack)
            {
                Bytes[1] |= 0b_1000_0000;
            }
            if (install)
            {
                Bytes[1] |= 0b_0100_0000;
            }
            Bytes[1] |= (byte)(keyIndex << 4);
            if (keyType)
            {
                // Bytes[1] |= 0b_0001_0000;
                Bytes[1] |= 0b_0000_1000;
            }
            Bytes[1] |= keyDescriptorNumber;
        }
        /// <summary>
        /// The byte array from which all the fields are read.
        /// </summary>
        public readonly byte[] Bytes;
        /// <summary>
        /// Set to 1 by the supplicant (STA) to request the authenticator (AP) initiate a new 
        /// 4-way handshake, otherwise 0.
        /// </summary>
        public bool Request
        {
            get { return (Bytes[0] & 0b_0000_1000) != 0; }
        }
        /// <summary>
        /// Set to 1 by a party when it detected some error in the message received, otherwise
        /// 0.
        /// </summary>
        public bool Error 
        {
            get { return (Bytes[0] & 0b_0000_0100) != 0; }
        }
        /// <summary>
        /// Set to 1 when the 4-way handshake completes to indicate that further communications 
        /// will be secure (data encrypted), otherwise 0.
        /// </summary>
        public bool Secure 
        {
            get { return (Bytes[0] & 0b_0000_0010) != 0; }
        }
        /// <summary>
        /// Set to 1 if a MIC has been computed and inserted into the MIC field of the EAPOL-Key
        /// data frame, otherwise 0.
        /// </summary>
        public bool MIC
        {
            get { return (Bytes[0] & 0b_0000_0001) != 0; }
        }
        /// <summary>
        /// Set to 1 by the authenticator (AP) if it expects a response from the supplicant (STA),
        /// otherwise 0.
        /// </summary>
        public bool Ack 
        {
            get { return (Bytes[1] & 0b_1000_0000) != 0; }
        }
        /// <summary>
        /// Set to 1 if a new pairwise key should be installed, otherwise 0.
        /// </summary>
        public bool Install 
        {
            get { return (Bytes[1] & 0b_0100_0000) != 0; }
        }
        /// <summary>
        /// Indicates key index for group keys.
        /// </summary>
        public int KeyIndex 
        {
            get { return (Bytes[1] & 0b_0011_0000) >> 4; }
        }
        /// <summary>
        /// Set to 1 for pairwise and to 0 for group keys.
        /// </summary>
        public bool KeyType 
        {
            get { return (Bytes[1] & 0b_0000_1000) != 0; }
        }
        /// <summary>
        /// A number indicating the version and scheme of authentication used.
        /// </summary>
        public int KeyDescriptorTypeNumber
        {
            get { return Bytes[1] & 0b_0000_0111; }
        }
        public override bool Equals(object obj)
        {
            EAPOLKeyInformationField other = obj as EAPOLKeyInformationField;
            return Equals(other);
        }
        public bool Equals(EAPOLKeyInformationField other)
        {
            if (Object.ReferenceEquals(other, null))
            {
                return false;
            }
            if (object.ReferenceEquals(other, this))
            {
                return true;
            }
            if ((Bytes == null) || (other.Bytes == null))
            {
                return false;
            }
            if (Bytes.Length != other.Bytes.Length)
            {
                return false;
            }
            return (HelperMethods.CompareBuffers(Bytes, other.Bytes, Bytes.Length) == 0);
        }
        public static bool operator==(EAPOLKeyInformationField lhs, EAPOLKeyInformationField rhs)
        {
            if (object.ReferenceEquals(lhs, null))
            {
                if (object.ReferenceEquals(rhs, null))
                {
                    return true;
                }
                return false;
            }
            return lhs.Equals(rhs);
        }
        public static bool operator!=(EAPOLKeyInformationField lhs, EAPOLKeyInformationField rhs)
        {
            return !(lhs == rhs);
        }
        public override int GetHashCode()
        {
            IStructuralEquatable bytesEquatable = Bytes as IStructuralEquatable;
            return bytesEquatable.GetHashCode(EqualityComparer<byte>.Default);
        }
    }
}
