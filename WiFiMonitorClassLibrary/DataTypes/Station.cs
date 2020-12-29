
namespace WiFiMonitorClassLibrary.DataTypes
{
    public class Station
    {
        public byte[] ANonce { get; set; }
        public byte[] PairwiseTemporalKey { get; set; }
        public byte[] SNonce { get; set; }
    }
}