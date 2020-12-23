using System;
using System.Runtime.InteropServices;

namespace WiFiMonitorClassLibrary
{
    /// <summary>
    /// A static class containing various miscellanious helper methods.
    /// </summary>
    public static class HelperMethods
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr memcmp(byte[] b1, byte[] b2, UIntPtr count);

        /// <summary>
        /// A wrapper for memcmp in C#. Numerically compares two buffers of memory. 
        /// The buffers are compared up to the end of buffer1.
        /// </summary>
        /// <param name="buffer1">The first buffer.</param>
        /// <param name="buffer2">The second buffer</param>
        /// <returns>
        /// Returns 0 if the buffers are equal, < 0 if buffer2 is greater than buffer1, 
        /// and > 0 if buffer1 is greater than buffer2.
        /// </returns>
        public static int CompareBuffers(byte[] buffer1, byte[] buffer2)
        {
            IntPtr result = memcmp(buffer1, buffer2, new UIntPtr((uint)buffer1.Length));
            return result.ToInt32();
        }
        /// <summary>
        /// A wrapper of memcmp in C#. Numerically compares two buffers of memory. 
        /// The buffers are compared up to the end of buffer1.
        /// </summary>
        /// <param name="buffer1">The first buffer.</param>
        /// <param name="buffer2">The second buffer</param>
        /// <param name="lesserBuffer">The numerically lesser buffer.</param>
        /// <param name="greaterBuffer">The numarically greater buffer.</param>
        /// <returns>
        /// Returns 0 if the buffers are equal, < 0 if buffer2 is greater than buffer1, 
        /// and > 0 if buffer1 is greater than buffer2.
        /// </returns>
        public static int CompareBuffers(
            byte[] buffer1, 
            byte[] buffer2, 
            out byte[] lesserBuffer, 
            out byte[] greaterBuffer)
        {
            int result = CompareBuffers(buffer1, buffer2);
            if (result < 0)
            {
                lesserBuffer = buffer1;
                greaterBuffer = buffer2;
            }
            else
            {
                lesserBuffer = buffer2;
                greaterBuffer = buffer1;
            }
            return result;
        }
    }
}
