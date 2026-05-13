using net.redeemertech.Security.Model;

using Rock;
using Rock.Data;

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;

namespace net.redeemertech.Security
{
    public static class IISAlertBlockedIpCache
    {
        private static readonly ConcurrentDictionary<string, DateTime> BlockedIps = new ConcurrentDictionary<string, DateTime>( StringComparer.OrdinalIgnoreCase );
        private static readonly object LoadLock = new object();
        private static bool _isLoaded;

        public static void EnsureLoaded()
        {
            if ( _isLoaded )
            {
                return;
            }

            lock ( LoadLock )
            {
                if ( _isLoaded )
                {
                    return;
                }

                Reload();
                _isLoaded = true;
            }
        }

        public static void Reload()
        {
            var now = RockDateTime.Now;
            using ( var rockContext = new RockContext() )
            {
                var activeBlocks = new IISAlertBlockedIpService( rockContext ).Queryable()
                    .Where( b => b.ExpiresDateTime > now )
                    .GroupBy( b => b.IpAddress )
                    .Select( g => new
                    {
                        IpAddress = g.Key,
                        ExpiresDateTime = g.Max( b => b.ExpiresDateTime )
                    } )
                    .ToList();

                BlockedIps.Clear();
                foreach ( var block in activeBlocks )
                {
                    AddOrRefresh( block.IpAddress, block.ExpiresDateTime );
                }
            }
        }

        public static bool IsBlocked( string ipAddress )
        {
            EnsureLoaded();

            var normalizedIpAddress = NormalizeIpAddress( ipAddress );
            if ( normalizedIpAddress.IsNullOrWhiteSpace() )
            {
                return false;
            }

            DateTime expiresDateTime;
            if ( !BlockedIps.TryGetValue( normalizedIpAddress, out expiresDateTime ) )
            {
                return false;
            }

            if ( expiresDateTime > RockDateTime.Now )
            {
                return true;
            }

            Remove( normalizedIpAddress );
            return false;
        }

        public static void AddOrRefresh( string ipAddress, DateTime expiresDateTime )
        {
            var normalizedIpAddress = NormalizeIpAddress( ipAddress );
            if ( normalizedIpAddress.IsNullOrWhiteSpace() )
            {
                return;
            }

            BlockedIps.AddOrUpdate(
                normalizedIpAddress,
                expiresDateTime,
                ( key, currentExpiresDateTime ) => currentExpiresDateTime > expiresDateTime ? currentExpiresDateTime : expiresDateTime );
        }

        public static void Remove( string ipAddress )
        {
            var normalizedIpAddress = NormalizeIpAddress( ipAddress );
            if ( normalizedIpAddress.IsNullOrWhiteSpace() )
            {
                return;
            }

            DateTime ignored;
            BlockedIps.TryRemove( normalizedIpAddress, out ignored );
        }

        public static void RefreshIpAddress( string ipAddress )
        {
            var normalizedIpAddress = NormalizeIpAddress( ipAddress );
            if ( normalizedIpAddress.IsNullOrWhiteSpace() )
            {
                return;
            }

            var now = RockDateTime.Now;
            using ( var rockContext = new RockContext() )
            {
                var expiresDateTime = new IISAlertBlockedIpService( rockContext ).Queryable()
                    .Where( b => b.IpAddress == normalizedIpAddress && b.ExpiresDateTime > now )
                    .Select( b => ( DateTime? ) b.ExpiresDateTime )
                    .Max();

                if ( expiresDateTime.HasValue )
                {
                    AddOrRefresh( normalizedIpAddress, expiresDateTime.Value );
                }
                else
                {
                    Remove( normalizedIpAddress );
                }
            }
        }

        public static string NormalizeIpAddress( string ipAddress )
        {
            if ( ipAddress.IsNullOrWhiteSpace() )
            {
                return null;
            }

            IPAddress parsedIpAddress;
            return IPAddress.TryParse( ipAddress.Trim(), out parsedIpAddress ) ? parsedIpAddress.ToString() : null;
        }
    }
}
