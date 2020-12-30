using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace WiFiMonitorClassLibrary.Monitoring
{
    public class AccessPoint
    {
        public AccessPoint()
        {
            Stations = new Dictionary<PhysicalAddress, Station>();
        }
        public PhysicalAddress BSSID { get; private set; }
        public IDictionary<PhysicalAddress, Station> Stations { get; private set; }
    }
}