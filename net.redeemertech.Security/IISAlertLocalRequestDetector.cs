using System;
using System.Net;
using System.Web;

namespace net.redeemertech.Security
{
    internal static class IISAlertLocalRequestDetector
    {
        internal static bool IsLocalRequest( HttpRequest request, string effectiveClientIpAddress )
        {
            if ( request == null )
            {
                return false;
            }

            return IsLocalRequest(
                request.ServerVariables["REMOTE_ADDR"],
                request.ServerVariables["LOCAL_ADDR"],
                effectiveClientIpAddress );
        }

        internal static bool IsLocalRequest( string remoteIpAddress, string localIpAddress, string effectiveClientIpAddress )
        {
            IPAddress remoteAddress;
            IPAddress localAddress;
            IPAddress effectiveClientAddress;
            if ( !TryParse( remoteIpAddress, out remoteAddress )
                || !TryParse( effectiveClientIpAddress, out effectiveClientAddress ) )
            {
                return false;
            }

            var hasLocalAddress = TryParse( localIpAddress, out localAddress );
            var transportIsLocal = IPAddress.IsLoopback( remoteAddress )
                || ( hasLocalAddress && AddressesEqual( remoteAddress, localAddress ) );
            if ( !transportIsLocal )
            {
                return false;
            }

            return IPAddress.IsLoopback( effectiveClientAddress )
                || ( hasLocalAddress && AddressesEqual( effectiveClientAddress, localAddress ) );
        }

        private static bool TryParse( string value, out IPAddress address )
        {
            if ( !IPAddress.TryParse( value == null ? null : value.Trim(), out address ) )
            {
                return false;
            }

            address = Normalize( address );
            return true;
        }

        private static bool AddressesEqual( IPAddress first, IPAddress second )
        {
            return Normalize( first ).Equals( Normalize( second ) );
        }

        private static IPAddress Normalize( IPAddress address )
        {
            return address != null && address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        }
    }
}
