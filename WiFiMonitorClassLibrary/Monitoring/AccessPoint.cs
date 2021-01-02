using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace WiFiMonitorClassLibrary.Monitoring
{
    public class AccessPoint
    {
        public AccessPoint(PhysicalAddress bssid)
        {
            BSSID = bssid;
        }
        public PhysicalAddress BSSID { get; }
        public byte[] PairwiseMasterKey { get; set; }
    }
}