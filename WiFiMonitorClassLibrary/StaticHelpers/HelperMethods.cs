using System;
using System.Runtime.InteropServices;

namespace WiFiMonitorClassLibrary.StaticHelpers
{
    /// <summary>
    /// A static class containing various miscellanious helper methods.
    /// </summary>
    public static class HelperMethods
    {
        [DllImport("libc", EntryPoint = "memcmp", CallingConvention = CallingConvention.Cdecl)]
        private static extern int MemcmpUnix(byte[] b1, byte[] b2, int count);

        [DllImport("msvcrt.dll", EntryPoint = "memcmp", CallingConvention = CallingConvention.Cdecl)]
        private static extern int MemcmpWindows(byte[] b1, byte[] b2, int count);

        /// <summary>
        /// A C# wrapper for memcmp. Numerically compares two buffers of memory.
        /// </summary>
        /// <param name="buffer1">The first buffer to compare.</param>
        /// <param name="buffer2">The second buffer to compare.</param>
        /// <param name="count">The amount of bytes to compare from both buffers.</param>
        /// <returns>
        /// 0 if the buffers are equal. < 0 if buffer1 is less than buffer2, > 0 if buffer1
        /// is greater than buffer2.
        /// </returns>
        public static int CompareBuffers(byte[] buffer1, byte[] buffer2, int count)
        {
            int result;
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                result = MemcmpUnix(buffer1, buffer2, count);
            }
            else 
            {
                result = MemcmpWindows(buffer1, buffer2, count);
            }
            return result;
        }
        /// <summary>
        /// A C# wrapper for memcmp. Numerically compares two buffers of memory.
        /// </summary>
        /// <param name="buffer1">The first buffer to compare.</param>
        /// <param name="buffer2">The second buffer to compare.</param>
        /// <param name="lesserBuffer">The numerically lesser buffer.</param>
        /// <param name="greaterBuffer">The numerically greater buffer.</param>
        /// <returns>
        /// 0 if the buffers are equal. < 0 if buffer1 is less than buffer2, > 0 if buffer1
        /// is greater than buffer2.
        /// </returns>
        public static int CompareBuffers(
            byte[] buffer1, 
            byte[] buffer2, 
            out byte[] lesserBuffer, 
            out byte[] greaterBuffer)
        {
            int result = CompareBuffers(buffer1, buffer2, buffer1.Length);
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
