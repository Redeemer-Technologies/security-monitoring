using net.redeemertech.Security.Model;

using Rock;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class IISBlockedIpBag
    {
        public string IdKey { get; set; }
        public string IpAddress { get; set; }
        public string AlertName { get; set; }
        public string BlockedDateTime { get; set; }
        public string ExpiresDateTime { get; set; }
        public string Status { get; set; }
        public string HistoryIdKey { get; set; }

        public static IISBlockedIpBag FromEntity( IISAlertBlockedIp blockedIp )
        {
            return new IISBlockedIpBag
            {
                IdKey = blockedIp.IdKey,
                IpAddress = blockedIp.IpAddress,
                AlertName = blockedIp.AlertName,
                BlockedDateTime = blockedIp.BlockedDateTime.ToString( "g" ),
                ExpiresDateTime = blockedIp.ExpiresDateTime.ToString( "g" ),
                Status = blockedIp.ExpiresDateTime > RockDateTime.Now ? "Active" : "Expired",
                HistoryIdKey = blockedIp.IISAlertHistory?.IdKey
            };
        }
    }
}
