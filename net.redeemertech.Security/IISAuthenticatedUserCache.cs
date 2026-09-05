using Rock.Data;
using Rock.Model;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace net.redeemertech.Security
{
    /// <summary>
    /// Maintains the small username-to-person mapping needed by request rules without
    /// retaining Entity Framework entities or querying the database on the request path.
    /// </summary>
    internal static class IISAuthenticatedUserCache
    {
        private static readonly object LoadLock = new object();
        private static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes( 5 );
        private static readonly TimeSpan RefreshFailureRetryInterval = TimeSpan.FromMinutes( 1 );

        private static volatile Dictionary<string, Guid> _personGuidsByUserName =
            new Dictionary<string, Guid>( StringComparer.OrdinalIgnoreCase );
        private static volatile bool _isLoaded;
        private static long _refreshAfterUtcTicks;
        private static int _refreshQueued;

        public static void EnsureLoaded()
        {
            if ( _isLoaded )
            {
                return;
            }

            if ( DateTime.UtcNow.Ticks < Interlocked.Read( ref _refreshAfterUtcTicks ) )
            {
                return;
            }

            lock ( LoadLock )
            {
                if ( !_isLoaded && DateTime.UtcNow.Ticks >= Interlocked.Read( ref _refreshAfterUtcTicks ) )
                {
                    try
                    {
                        Reload();
                    }
                    catch ( Exception ex )
                    {
                        Interlocked.Exchange( ref _refreshAfterUtcTicks, DateTime.UtcNow.Add( RefreshFailureRetryInterval ).Ticks );
                        IISAlertFailureHandling.LogFailOpen( IISAlertRuntime.ExceptionLogger, "authenticated-user cache load", ex );
                    }
                }
            }
        }

        public static bool TryGetPersonGuid( string userName, out Guid personGuid )
        {
            personGuid = Guid.Empty;
            if ( string.IsNullOrWhiteSpace( userName ) )
            {
                return false;
            }

            EnsureLoaded();
            QueueRefreshIfExpired();
            return _personGuidsByUserName.TryGetValue( userName, out personGuid );
        }

        public static void Reload()
        {
            Dictionary<string, Guid> replacement;
            using ( var rockContext = new RockContext() )
            {
                var users = new UserLoginService( rockContext ).Queryable()
                    .Where( user => user.PersonId.HasValue && user.UserName != null && user.UserName != string.Empty )
                    .Select( user => new
                    {
                        user.UserName,
                        PersonGuid = user.Person.Guid
                    } )
                    .ToList();

                replacement = new Dictionary<string, Guid>( StringComparer.OrdinalIgnoreCase );
                foreach ( var user in users )
                {
                    replacement[user.UserName] = user.PersonGuid;
                }
            }

            _personGuidsByUserName = replacement;
            Interlocked.Exchange( ref _refreshAfterUtcTicks, DateTime.UtcNow.Add( RefreshInterval ).Ticks );
            _isLoaded = true;
        }

        private static void QueueRefreshIfExpired()
        {
            if ( DateTime.UtcNow.Ticks < Interlocked.Read( ref _refreshAfterUtcTicks )
                || Interlocked.CompareExchange( ref _refreshQueued, 1, 0 ) != 0 )
            {
                return;
            }

            ThreadPool.QueueUserWorkItem( ignored =>
            {
                try
                {
                    Reload();
                }
                catch ( Exception ex )
                {
                    Interlocked.Exchange( ref _refreshAfterUtcTicks, DateTime.UtcNow.Add( RefreshFailureRetryInterval ).Ticks );
                    IISAlertFailureHandling.LogFailOpen( IISAlertRuntime.ExceptionLogger, "authenticated-user cache refresh", ex );
                }
                finally
                {
                    Interlocked.Exchange( ref _refreshQueued, 0 );
                }
            } );
        }
    }
}
