using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using DuckDB.NET.Data;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class IISLogDuckDbQueryTests
    {
        private readonly List<string> _tempFolders = new List<string>();

        [TestCleanup]
        public void Cleanup()
        {
            foreach ( var tempFolder in _tempFolders )
            {
                if ( Directory.Exists( tempFolder ) )
                {
                    Directory.Delete( tempFolder, true );
                }
            }
        }

        [TestMethod]
        public void PrepareQueryRequiresLogsPlaceholderExactlyOnce()
        {
            var query = new IISLogDuckDbQuery();
            var folder = CreateTempFolder();
            CreateFile( folder, DateTime.Today.ToString( "yyyyMMdd" ) + ".parquet" );

            AssertExceptionMessage( () => query.PrepareQuery( "SELECT 1", IISLogDuckDbQuery.DefaultDateRange, folder, 100 ), "must include [[logs]]" );
            AssertExceptionMessage( () => query.PrepareQuery( "SELECT * FROM [[logs]] UNION ALL SELECT * FROM [[logs]]", IISLogDuckDbQuery.DefaultDateRange, folder, 100 ), "exactly once" );
        }

        [TestMethod]
        public void PrepareQueryRejectsNonSelectAndMultipleStatements()
        {
            var query = new IISLogDuckDbQuery();
            var folder = CreateTempFolder();
            CreateFile( folder, DateTime.Today.ToString( "yyyyMMdd" ) + ".parquet" );

            AssertExceptionMessage( () => query.PrepareQuery( "DELETE FROM [[logs]]", IISLogDuckDbQuery.DefaultDateRange, folder, 100 ), "Only SELECT queries are allowed" );
            AssertExceptionMessage( () => query.PrepareQuery( "SELECT * FROM [[logs]]; SELECT 1", IISLogDuckDbQuery.DefaultDateRange, folder, 100 ), "Only one SQL statement is allowed" );
        }

        [TestMethod]
        public void PrepareQueryReplacesPlaceholderWithEscapedMatchingParquetFiles()
        {
            var query = new IISLogDuckDbQuery();
            var folder = CreateTempFolder( "iis logs 'quoted'" );
            var today = DateTime.Today.ToString( "yyyyMMdd" );
            var includedFile = CreateFile( folder, today + "_main.parquet" );
            CreateFile( Path.Combine( folder, "temp" ), today + "_temp.parquet" );
            CreateFile( folder, "not-a-date.parquet" );

            var preparedQuery = query.PrepareQuery( "SELECT * FROM [[logs]];", "-1||||", folder, 100 );

            StringAssert.Contains( preparedQuery, "read_parquet" );
            StringAssert.Contains( preparedQuery, includedFile.Replace( "'", "''" ) );
            Assert.AreEqual( 1, CountOccurrences( preparedQuery, ".parquet" ) );
            Assert.IsFalse( preparedQuery.Contains( "[[logs]]" ) );
        }

        [TestMethod]
        public void GetParquetFilesOrdersByPathAndHonorsMaximumFileCount()
        {
            var query = new IISLogDuckDbQuery();
            var folder = CreateTempFolder();
            var today = DateTime.Today.ToString( "yyyyMMdd" );
            var laterFile = CreateFile( folder, today + "_b.parquet" );
            var earlierFile = CreateFile( folder, today + "_a.parquet" );
            CreateFile( folder, today + "_c.parquet" );

            var files = query.GetParquetFiles( "-1||||", folder, 2 );

            CollectionAssert.AreEqual( new[] { earlierFile, laterFile }, files );
        }

        [TestMethod]
        public void ExecutePreparedQuerySupportsParametersAndSchemaOnlyResults()
        {
            var query = new IISLogDuckDbQuery();
            var dataTable = query.ExecutePreparedQuery( "SELECT $name AS name, 42 AS value", 30, false, new Dictionary<string, object> { { "name", "Alice" } } );

            Assert.AreEqual( 0, dataTable.Rows.Count );
            Assert.AreEqual( 2, dataTable.Columns.Count );
            Assert.AreEqual( "name", dataTable.Columns[0].ColumnName );
            Assert.AreEqual( "value", dataTable.Columns[1].ColumnName );
        }

        [TestMethod]
        public void ExecutePreparedQueryConvertsDuckDbTimeValuesToStrings()
        {
            var query = new IISLogDuckDbQuery();
            var dataTable = query.ExecutePreparedQuery( "SELECT TIME '12:34:56.123456' AS request_time", 30 );

            Assert.AreEqual( typeof( string ), dataTable.Columns[0].DataType );
            Assert.AreEqual( "12:34:56.123456", dataTable.Rows[0][0] );
        }

        [TestMethod]
        public void ExecuteAddsImpersonatedPersonIdColumnForRckipidUserNames()
        {
            var folder = CreateTempFolder();
            CreateParquetFile(
                folder,
                DateTime.Today.ToString( "yyyyMMdd" ) + "_users.parquet",
                "SELECT 'rckipid=token-a' AS \"cs-username\" UNION ALL SELECT 'regular-user' AS \"cs-username\"" );

            var query = new TestableIISLogDuckDbQuery( new Dictionary<string, int> { { "rckipid=token-a", 42 } } );

            var dataTable = query.Execute( "SELECT impersonated_person_id FROM [[logs]] WHERE impersonated_person_id = 42", "-1||||", folder, 100, 30 );

            Assert.AreEqual( 1, dataTable.Rows.Count );
            Assert.AreEqual( 42, dataTable.Rows[0]["impersonated_person_id"] );
        }

        private string CreateTempFolder( string name = null )
        {
            var folder = Path.Combine( Path.GetTempPath(), "IISLogDuckDbQueryTests", Guid.NewGuid().ToString( "N" ), name ?? "logs" );
            Directory.CreateDirectory( folder );
            _tempFolders.Add( Directory.GetParent( folder ).FullName );
            return folder;
        }

        private static string CreateFile( string folder, string fileName )
        {
            Directory.CreateDirectory( folder );
            var filePath = Path.Combine( folder, fileName );
            File.WriteAllText( filePath, string.Empty );
            return filePath;
        }

        private static string CreateParquetFile( string folder, string fileName, string sourceQuery )
        {
            Directory.CreateDirectory( folder );
            var filePath = Path.Combine( folder, fileName );
            DuckDbNativeLibrary.EnsureLoaded();

            using ( var connection = new DuckDBConnection( "Data Source=:memory:" ) )
            {
                connection.Open();
                using ( var command = connection.CreateCommand() )
                {
                    command.CommandText = string.Format( "COPY ({0}) TO '{1}' (FORMAT PARQUET)", sourceQuery, filePath.Replace( "'", "''" ) );
                    command.ExecuteNonQuery();
                }
            }

            return filePath;
        }

        private static int CountOccurrences( string value, string text )
        {
            var count = 0;
            var index = 0;
            while ( ( index = value.IndexOf( text, index, StringComparison.OrdinalIgnoreCase ) ) >= 0 )
            {
                count++;
                index += text.Length;
            }

            return count;
        }

        private static void AssertExceptionMessage( Action action, string expectedMessagePart )
        {
            var exception = Assert.ThrowsException<InvalidOperationException>( action );
            StringAssert.Contains( exception.Message, expectedMessagePart );
        }

        private class TestableIISLogDuckDbQuery : IISLogDuckDbQuery
        {
            private readonly Dictionary<string, int> _personIdsByUserName;

            public TestableIISLogDuckDbQuery( Dictionary<string, int> personIdsByUserName )
            {
                _personIdsByUserName = personIdsByUserName;
            }

            protected override int? ResolveImpersonatedPersonId( string csUserName )
            {
                int personId;
                return _personIdsByUserName.TryGetValue( csUserName, out personId ) ? personId : ( int? ) null;
            }
        }
    }
}
