using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class IISAlertLocalRequestDetectorTests
    {
        [TestMethod]
        public void LoopbackAndSameMachineConnectionsAreLocal()
        {
            Assert.IsTrue( IISAlertLocalRequestDetector.IsLocalRequest( "127.0.0.1", "127.0.0.1", "127.0.0.1" ) );
            Assert.IsTrue( IISAlertLocalRequestDetector.IsLocalRequest( "::1", "::1", "::1" ) );
            Assert.IsTrue( IISAlertLocalRequestDetector.IsLocalRequest( "::ffff:127.0.0.1", "127.0.0.1", "127.0.0.1" ) );
            Assert.IsTrue( IISAlertLocalRequestDetector.IsLocalRequest( "192.0.2.10", "192.0.2.10", "192.0.2.10" ) );
        }

        [TestMethod]
        public void ExternalAndProxiedExternalConnectionsAreNotLocal()
        {
            Assert.IsFalse( IISAlertLocalRequestDetector.IsLocalRequest( "198.51.100.20", "192.0.2.10", "127.0.0.1" ) );
            Assert.IsFalse( IISAlertLocalRequestDetector.IsLocalRequest( "127.0.0.1", "127.0.0.1", "198.51.100.20" ) );
            Assert.IsFalse( IISAlertLocalRequestDetector.IsLocalRequest( null, "127.0.0.1", "127.0.0.1" ) );
        }
    }
}
