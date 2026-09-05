using Rock.Model;

using System;
using System.Diagnostics;

namespace net.redeemertech.Security
{
    internal interface IIISAlertExceptionLogger
    {
        void Log( Exception exception );
    }

    internal sealed class IISAlertExceptionLogger : IIISAlertExceptionLogger
    {
        public void Log( Exception exception )
        {
            ExceptionLogService.LogException( exception );
        }
    }

    internal static class IISAlertFailureHandling
    {
        internal static void LogFailOpen( IIISAlertExceptionLogger logger, string operation, Exception exception )
        {
            LogSafely(
                logger,
                new Exception(
                    string.Format( "Real-time IIS request filtering failed open during {0}.", operation ),
                    exception ) );
        }

        internal static void LogSafely( IIISAlertExceptionLogger logger, Exception exception )
        {
            try
            {
                logger.Log( exception );
            }
            catch ( Exception loggingException )
            {
                Trace.TraceError(
                    "Unable to record a real-time IIS request-filter failure. Original: {0} Logging: {1}",
                    exception,
                    loggingException );
            }
        }
    }
}
