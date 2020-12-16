using System;
using System.Collections.Generic;
using System.Text;

namespace WiFiMonitorClassLibrary
{
    public class PacketArrivedEventArgs : EventArgs
    {
        public PacketArrivedEventArgs()
        {
            Bla = "bla";
        }
        public PacketArrivedEventArgs(string bla)
        {
            Bla = bla;
        }

        public string Bla { get; }
    }
}
