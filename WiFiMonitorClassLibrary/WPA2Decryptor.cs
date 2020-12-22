using PacketDotNet.Ieee80211;
using System;

namespace WiFiMonitorClassLibrary
{
    public static class WPA2Dectyptor
    {
        /// <summary>
        /// Decrypts a PacketDotNet IEEE 802.11 DataFrame using CCMP decryption.
        /// </summary>
        /// <param name="frameToDecrypt">The frame to decrypt.</param>
        /// <param name="temporalKey">The temporal key used in encrypting the frame.</param>
        /// <param name="nonce">The "number used only once" used in encrypting the frame.</param>
        /// <returns>The decrypted frame.</returns>
        public static T CCMPDecryptDataFrame<T>(
            T frameToDecrypt, 
            byte[] temporalKey,
            byte[] nonce) 
        where T : DataFrame
        {
            if (frameToDecrypt.FrameControl.Protected == false)
            {
                return frameToDecrypt;
            }
            throw new NotImplementedException("CCMPDecryptDataFrame is yet to be implemented.");
        }
    }
}