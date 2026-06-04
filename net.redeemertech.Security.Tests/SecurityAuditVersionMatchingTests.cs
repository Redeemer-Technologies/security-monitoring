using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class SecurityAuditVersionMatchingTests
    {
        private static readonly object SecurityAudit = FormatterServices.GetUninitializedObject( typeof( SecurityAudit ) );

        [TestMethod]
        public void GetLatestSecurityPluginVersionReturnsExactRockVersionMatch()
        {
            var versionData = LoadVersionData( "security-plugin-versions-basic.json" );
            var latestVersion = InvokePrivate<string>( "GetLatestSecurityPluginVersion", versionData, "17.6.0" );

            Assert.AreEqual( "17.6.2.0", latestVersion );
        }

        [TestMethod]
        public void GetLatestSecurityPluginVersionReturnsEmptyStringWhenRockVersionIsMissing()
        {
            var versionData = LoadVersionData( "security-plugin-versions-basic.json" );
            var latestVersion = InvokePrivate<string>( "GetLatestSecurityPluginVersion", versionData, "17.6.1" );

            Assert.AreEqual( string.Empty, latestVersion );
        }

        [TestMethod]
        public void GetSecurityPluginNoticesReturnsArrayNoticesForExactRockVersion()
        {
            var versionData = LoadVersionData( "security-plugin-versions-notices.json" );
            var notices = InvokePrivate<List<string>>( "GetSecurityPluginNotices", versionData, "17.6.0" );

            CollectionAssert.AreEqual(
                new[]
                {
                    "Security plugin 17.6.2.0 fixes CVE-0001.",
                    "Rotate exposed security tokens after upgrading."
                },
                notices );
        }

        [TestMethod]
        public void GetSecurityPluginNoticesReturnsSingleNoticeStrings()
        {
            var versionData = LoadVersionData( "security-plugin-versions-notices.json" );
            var notices = InvokePrivate<List<string>>( "GetSecurityPluginNotices", versionData, "17.5.0" );

            CollectionAssert.AreEqual( new[] { "Upgrade to 17.5.4.0 before installing 17.6." }, notices );
        }

        [TestMethod]
        public void GetSecurityPluginNoticesIgnoresBlankNoticeValues()
        {
            var versionData = LoadVersionData( "security-plugin-versions-notices.json" );
            var notices = InvokePrivate<List<string>>( "GetSecurityPluginNotices", versionData, "17.4.0" );

            Assert.AreEqual( 0, notices.Count );
        }

        [TestMethod]
        public void CompareVersionsComparesSemanticVersionsNumerically()
        {
            Assert.IsTrue( InvokePrivate<int>( "CompareVersions", "17.6.10.0", "17.6.2.0" ) > 0, "Expected 17.6.10.0 to be newer than 17.6.2.0." );
            Assert.IsTrue( InvokePrivate<int>( "CompareVersions", "17.6.0.0", "17.6.0.0" ) == 0, "Expected equal semantic versions to compare as equal." );
            Assert.IsTrue( InvokePrivate<int>( "CompareVersions", "17.6.0.0", "17.6.1.0" ) < 0, "Expected 17.6.0.0 to be older than 17.6.1.0." );
        }

        [TestMethod]
        public void CompareVersionsFallsBackToOrdinalTextComparison()
        {
            Assert.IsTrue( InvokePrivate<int>( "CompareVersions", "17.6.0-alpha", "17.6.0-beta" ) < 0, "Expected alpha to sort before beta." );
            Assert.IsTrue( InvokePrivate<int>( "CompareVersions", "17.6.0-RC", "17.6.0-rc" ) == 0, "Expected fallback comparison to ignore case." );
        }

        [TestMethod]
        public void GetKnownGoodLavaApprovalHashesIgnoresUnsupportedKnownGoodHashesSection()
        {
            var versionData = new Dictionary<string, object>
            {
                ["knownGoodHashes"] = new Dictionary<string, object>
                {
                    ["lavaApprovals"] = new object[]
                    {
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                        "not-a-sha256-hash",
                        " "
                    }
                }
            };

            var hashes = InvokePrivate<HashSet<string>>( "GetKnownGoodLavaApprovalHashes", versionData );

            Assert.AreEqual( 0, hashes.Count );
        }

        [TestMethod]
        public void GetKnownGoodLavaApprovalHashesReadsTopLevelArray()
        {
            var versionData = new Dictionary<string, object>
            {
                ["knownGoodLavaApprovalHashes"] = new object[]
                {
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                }
            };

            var hashes = InvokePrivate<HashSet<string>>( "GetKnownGoodLavaApprovalHashes", versionData );

            Assert.AreEqual( 1, hashes.Count );
            Assert.IsTrue( hashes.Contains( "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ) );
        }

        [DataTestMethod]
        [DataRow( "{{ Person.NickName }}" )]
        [DataRow( "{% assign firstName = Person.NickName %}" )]
        [DataRow( "{[ shortcode property:'value' ]}" )]
        public void ContainsApprovalRequiredLavaReturnsTrueForLavaDelimiters( string content )
        {
            Assert.IsTrue( InvokePrivate<bool>( "ContainsApprovalRequiredLava", content ) );
        }

        [DataTestMethod]
        [DataRow( null )]
        [DataRow( "" )]
        [DataRow( "   " )]
        [DataRow( "{\"name\":\"Alice\",\"roles\":[\"admin\",\"editor\"]}" )]
        [DataRow( "{ \"query\": { \"term\": \"lava\" } }" )]
        [DataRow( "{not lava}" )]
        [DataRow( "JSON array [1, 2, 3] and object {\"value\": true}" )]
        public void ContainsApprovalRequiredLavaReturnsFalseForNonLavaContent( string content )
        {
            Assert.IsFalse( InvokePrivate<bool>( "ContainsApprovalRequiredLava", content ) );
        }

        [DataTestMethod]
        [DataRow( "RockEntity" )]
        [DataRow( " RockEntity " )]
        [DataRow( "rockentity" )]
        public void DefaultEnabledLavaCommandsAllowsOnlyEntityCommandsReturnsTrueForOnlyRockEntity( string enabledCommands )
        {
            Assert.IsTrue( InvokePrivate<bool>( "DefaultEnabledLavaCommandsAllowsOnlyEntityCommands", enabledCommands ) );
        }

        [DataTestMethod]
        [DataRow( null )]
        [DataRow( "" )]
        [DataRow( "   " )]
        [DataRow( "All" )]
        [DataRow( "Sql" )]
        [DataRow( "RockEntity,Sql" )]
        [DataRow( "Sql,RockEntity" )]
        public void DefaultEnabledLavaCommandsAllowsOnlyEntityCommandsReturnsFalseForOtherValues( string enabledCommands )
        {
            Assert.IsFalse( InvokePrivate<bool>( "DefaultEnabledLavaCommandsAllowsOnlyEntityCommands", enabledCommands ) );
        }

        /// <summary>
        /// Loads version data from a fixture file in the test project's Fixtures directory.
        /// </summary>
        private static Dictionary<string, object> LoadVersionData( string fileName )
        {
            var path = GetFixturePath( fileName );
            var json = File.ReadAllText( path );
            var serializer = new JavaScriptSerializer();

            return ( Dictionary<string, object> )serializer.DeserializeObject( json );
        }

        /// <summary>
        /// Resolves the fixture file path by walking up from the test runtime directory
        /// until the project-level Fixtures directory is found.
        /// </summary>
        private static string GetFixturePath( string fileName )
        {
            var currentDirectory = new DirectoryInfo( AppDomain.CurrentDomain.BaseDirectory );

            while ( currentDirectory != null )
            {
                var candidatePath = Path.Combine( currentDirectory.FullName, "Fixtures", fileName );
                if ( File.Exists( candidatePath ) )
                {
                    return candidatePath;
                }

                currentDirectory = currentDirectory.Parent;
            }

            throw new FileNotFoundException( "Fixture file was not found.", fileName );
        }

        private static T InvokePrivate<T>( string methodName, params object[] args )
        {
            var method = typeof( SecurityAudit ).GetMethod( methodName, BindingFlags.Instance | BindingFlags.NonPublic );
            if ( method == null )
            {
                throw new InvalidOperationException( "Method not found: " + methodName );
            }

            return ( T )method.Invoke( SecurityAudit, args );
        }
    }
}
