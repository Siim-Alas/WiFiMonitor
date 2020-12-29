using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace WiFiMonitorClassLibrary.DataTypes
{
    public class AccessPoint
    {
        public PhysicalAddress BSSID { get; private set; }
        public PhysicalAddress MACAddress { get; private set; }
        public IDictionary<PhysicalAddress, Station> Stations { get; private set; }
    }
}