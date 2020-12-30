using PacketDotNet.Ieee80211;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using WiFiMonitorClassLibrary.Parsing;

namespace WiFiMonitorClassLibrary.Monitoring
{
    public class NetworkGraph
    {
        public NetworkGraph()
        {
            AccessPoints = new Dictionary<PhysicalAddress, AccessPoint>();
        }
        public IDictionary<PhysicalAddress, AccessPoint> AccessPoints { get; }
        public void HandlePacketArrived(object sender, PacketArrivedEventArgs e)
        {
            MacFrame frame = e.ArrivedPacket.Extract<MacFrame>();
            switch (frame)
            {
                case DataFrame dataFrame:
                    HandleDataFrame(dataFrame);
                    break;
                case ManagementFrame managementFrame:

                    break;
                default:
                    break;
            }
        }
        private void AddDestinationAndSourceToGraph(
            DataFrame dataFrame, 
            out AccessPoint accessPoint,
            out Station station)
        {
            PhysicalAddress destinationAddress = dataFrame.DestinationAddress;
            PhysicalAddress sourceAddress = dataFrame.SourceAddress;

            if (AccessPoints.TryGetValue(destinationAddress, out accessPoint))
            {
                if (accessPoint.Stations.TryGetValue(sourceAddress, out station) == false)
                {
                    // The access point is recognized, but the station is not
                    station = new Station();
                    accessPoint.Stations[sourceAddress] = station;
                }
                // Both are recognized, so nothing needs to be done
            }
            else if (AccessPoints.TryGetValue(sourceAddress, out accessPoint))
            {
                if (accessPoint.Stations.TryGetValue(destinationAddress, out station) == false)
                {
                    // The access point is recognized, but the station is not
                    station = new Station();
                    accessPoint.Stations[destinationAddress] = station;
                }
                // Both are recognized, so nothing needs to be done
            }
            else
            {
                // The access point was not recognized, so both it and the station
                // need to be added
                accessPoint = new AccessPoint();
                station = new Station();

                if (dataFrame.FrameControl.ToDS)
                {
                    // The destination is an access point
                    AccessPoints[destinationAddress] = accessPoint;
                    AccessPoints[destinationAddress].Stations[sourceAddress] = station;
                }
                else 
                {
                    // The source is an access point
                    AccessPoints[sourceAddress] = accessPoint;
                    AccessPoints[sourceAddress].Stations[destinationAddress] = station;
                }
            }
        }
        private void HandleDataFrame(DataFrame dataFrame)
        {
            AddDestinationAndSourceToGraph(
                dataFrame, out AccessPoint accessPoint, out Station station);
            int handshakeNum = 
                FrameParser.TryToParse4WayHandshake(dataFrame, out EAPOLKeyFormat keyFormat);
            switch (handshakeNum)
            {
                case 1:
                    System.Console.WriteLine("setting ANonce");
                    station.ANonce = keyFormat.KeyNonce;
                    break;
                case 2:
                    System.Console.WriteLine("setting SNonce");
                    station.SNonce = keyFormat.KeyNonce;
                    break;
                case 3:
                    break;
                case 4:
                    break;
                default:
                    break;
            }
        }
    }
}