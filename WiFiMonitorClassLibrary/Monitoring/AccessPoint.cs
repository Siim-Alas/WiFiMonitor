using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace WiFiMonitorClassLibrary.Monitoring
{
    public class AccessPoint
    {
        public AccessPoint(PhysicalAddress bssid)
        {
            BSSID = bssid;
            Stations = new Dictionary<PhysicalAddress, Station>();
        }
        public PhysicalAddress BSSID { get; }
        public byte[] PairwiseMasterKey { get; set; }
        public IDictionary<PhysicalAddress, Station> Stations { get; }
    }
}