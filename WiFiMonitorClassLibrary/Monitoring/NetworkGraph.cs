using PacketDotNet.Ieee80211;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using WiFiMonitorClassLibrary.Cryptography;
using WiFiMonitorClassLibrary.Parsing;

namespace WiFiMonitorClassLibrary.Monitoring
{
    /// <summary>
    /// A class representing a network graph, that stores various details (Nonces, keys, etc.)
    /// on the access points and stations in a network.
    /// </summary>
    public class NetworkGraph
    {
        /// <summary>
        /// Constructs a new NetworkGraph instance, with empty AccessPoints.
        /// </summary>
        public NetworkGraph()
        {
            AccessPoints = new Dictionary<PhysicalAddress, AccessPoint>();
        }
        /// <summary>
        /// The access points in the network graph.
        /// </summary>
        public IDictionary<PhysicalAddress, AccessPoint> AccessPoints { get; }
        /// <summary>
        /// Adds a Pairwise Master Key (PMK) to the access point with the specified BSSID.
        /// In WPA2, the PMK is derived from the access point BSSID and password and used to 
        /// create other keys used in encryption.
        /// </summary>
        /// <param name="bssid">The BSSID of the access point.</param>
        /// <param name="password">The password of the access point.</param>
        public void AddPassword(string bssid, string password)
        {
            PhysicalAddress physicalAddressBSSID = PhysicalAddress.Parse(bssid);
            AddPassword(physicalAddressBSSID, password);
        }
        /// <summary>
        /// Adds a Pairwise Master Key (PMK) to the access point with the specified BSSID.
        /// In WPA2, the PMK is derived from the access point BSSID and password and used to 
        /// create other keys used in encryption.
        /// </summary>
        /// <param name="bssid">The BSSID of the access point.</param>
        /// <param name="password">The password of the access point.</param>
        public void AddPassword(PhysicalAddress bssid, string password)
        {
            byte[] pmk = 
                WPA2CryptographyTools.GeneratePairwiseMasterKey(bssid.GetAddressBytes(), password);
            if (AccessPoints.ContainsKey(bssid) == false)
            {
                AccessPoints[bssid] = new AccessPoint(bssid);
            }
            AccessPoints[bssid].PairwiseMasterKey = pmk;
        }
        /// <summary>
        /// Gets the destination and source of a PacketDotNet IEEE 802.11 DataFrame.
        /// The destination and source are determined by the return value. <br />
        /// If no access point or station with MAC addresses matching those in the dataFrame
        /// are found in the existing network graph, then the corresponding access point and
        /// station are added to the graph.
        /// </summary>
        /// <param name="dataFrame">The frame whose destination and source to get.</param>
        /// <param name="accessPoint">The access point to or from which the message is sent.</param>
        /// <param name="station">The station to or from which the message is sent.</param>
        /// <returns>True, if the access point is the destination. Otherwise, false.</returns>
        public bool GetDestinationAndSource(
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
                return true;
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
                return false;
            }
            else
            {
                // The access point was not recognized, so both it and the station
                // need to be added
                station = new Station();

                if (dataFrame.FrameControl.ToDS)
                {
                    // The destination is an access point
                    accessPoint = new AccessPoint(destinationAddress);
                    AccessPoints[destinationAddress] = accessPoint;
                    AccessPoints[destinationAddress].Stations[sourceAddress] = station;

                    return true;
                }
                else 
                {
                    // The source is an access point
                    accessPoint = new AccessPoint(sourceAddress);
                    AccessPoints[sourceAddress] = accessPoint;
                    AccessPoints[sourceAddress].Stations[destinationAddress] = station;

                    return false;
                }
            }
        }
        private void HandleDataFrame(DataFrame dataFrame)
        {
            GetDestinationAndSource(
                dataFrame, out AccessPoint accessPoint, out Station station);
            int handshakeNum = 
                FrameParser.TryToParse4WayHandshake(dataFrame, out EAPOLKeyFormat keyFormat);
            switch (handshakeNum)
            {
                case 1:
                    System.Console.WriteLine("Setting ANonce");

                    station.ANonce = keyFormat.KeyNonce;
                    break;
                case 2:
                    System.Console.WriteLine("Setting SNonce");

                    station.SNonce = keyFormat.KeyNonce;
                    if ((station.ANonce != null) && (accessPoint.PairwiseMasterKey != null))
                    {
                        byte[] ptk = WPA2CryptographyTools.GeneratePairwiseTemporalKey(
                            accessPoint.PairwiseMasterKey,
                            dataFrame.DestinationAddress.GetAddressBytes(),
                            dataFrame.SourceAddress.GetAddressBytes(),
                            station.ANonce,
                            station.SNonce);

                        System.Console.WriteLine("Setting ptk");
                        station.PairwiseTemporalKey = ptk;
                    }
                    break;
                case 3:
                    System.Console.WriteLine("4whs case 3");
                    break;
                case 4:
                    System.Console.WriteLine("4whs case 4");
                    break;
                default:
                    break;
            }
        }
        /// <summary>
        /// Uses the information contained in a PacketDotNet packet to update the
        /// network graph.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
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
    }
}