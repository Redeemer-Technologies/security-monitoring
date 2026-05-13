using DuckDB.NET.Data;

using Rock;
using Rock.Data;
using Rock.Enums.Controls;
using Rock.Model;
using Rock.ViewModels.Controls;

using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Hosting;

namespace net.redeemertech.Security
{
    public class IISLogDuckDbQuery
    {
        public const string LogsPlaceholder = "[[logs]]";
        public const string DefaultDateRange = "Last|7|Day||";
        private const string ImpersonationTokenTableName = "__impersonation_tokens";

        public DataTable Execute( string query, string dateRange, string parquetFolder, int maximumParquetFiles, int timeoutSeconds )
        {
            return Execute( query, dateRange, parquetFolder, maximumParquetFiles, timeoutSeconds, true, null );
        }

        public DataTable Execute( string query, string dateRange, string parquetFolder, int maximumParquetFiles, int timeoutSeconds, bool loadRows, Dictionary<string, object> sqlParameters )
        {
            var preparedQuery = PrepareQueryParts( query, dateRange, parquetFolder, maximumParquetFiles );
            return ExecutePreparedQuery( preparedQuery.Query, timeoutSeconds, loadRows, sqlParameters, preparedQuery.RawLogsSql );
        }

        public DataTable ExecutePreparedQuery( string preparedQuery, int timeoutSeconds, bool loadRows = true, Dictionary<string, object> sqlParameters = null )
        {
            return ExecutePreparedQuery( preparedQuery, timeoutSeconds, loadRows, sqlParameters, null );
        }

        private DataTable ExecutePreparedQuery( string preparedQuery, int timeoutSeconds, bool loadRows, Dictionary<string, object> sqlParameters, string rawLogsSql )
        {
            var sql = loadRows ? preparedQuery : "SELECT * FROM (" + preparedQuery + ") __log_query_schema LIMIT 0";

            using ( var connection = new DuckDBConnection( "Data Source=:memory:" ) )
            {
                connection.Open();
                CreateImpersonationTokenTable( connection );
                if ( loadRows )
                {
                    PopulateImpersonationTokenTable( connection, rawLogsSql );
                }

                using ( var command = connection.CreateCommand() )
                {
                    command.CommandText = sql;
                    command.CommandTimeout = timeoutSeconds;
                    AddSqlParameters( command, sqlParameters );

                    using ( var reader = command.ExecuteReader() )
                    {
                        return LoadDataTable( reader );
                    }
                }
            }
        }

        public string PrepareQuery( string query, string dateRange, string parquetFolder, int maximumParquetFiles )
        {
            return PrepareQueryParts( query, dateRange, parquetFolder, maximumParquetFiles ).Query;
        }

        private PreparedQuery PrepareQueryParts( string query, string dateRange, string parquetFolder, int maximumParquetFiles )
        {
            query = NormalizeQuery( query );
            if ( !query.Contains( LogsPlaceholder ) )
            {
                throw new InvalidOperationException( "The query must include [[logs]] as the placeholder for the IIS log parquet source." );
            }

            var placeholderCount = Regex.Matches( query, Regex.Escape( LogsPlaceholder ) ).Count;
            if ( placeholderCount != 1 )
            {
                throw new InvalidOperationException( "The query must include [[logs]] exactly once." );
            }

            if ( !Regex.IsMatch( query, @"^\s*(select|with)\b", RegexOptions.IgnoreCase ) )
            {
                throw new InvalidOperationException( "Only SELECT queries are allowed." );
            }

            var parquetFiles = GetParquetFiles( dateRange, parquetFolder, maximumParquetFiles );
            if ( !parquetFiles.Any() )
            {
                throw new InvalidOperationException( "No parquet files were found in the configured parquet folder for the selected date range." );
            }

            var fileList = "[" + parquetFiles.Select( f => "'" + EscapeSqlString( f ) + "'" ).JoinStrings( "," ) + "]";
            var rawLogsSql = GetRawLogsSql( fileList );
            var logsFromSql = "( SELECT __logs.*, __tokens.impersonated_person_id FROM " + rawLogsSql + " __logs LEFT JOIN " + ImpersonationTokenTableName + " __tokens ON __logs.\"cs-username\" = __tokens.cs_username )";
            return new PreparedQuery
            {
                Query = query.Replace( LogsPlaceholder, logsFromSql ),
                RawLogsSql = rawLogsSql
            };
        }

        public List<string> GetParquetFiles( string dateRange, string parquetFolder, int maximumParquetFiles )
        {
            parquetFolder = ResolveParquetFolder( parquetFolder );
            if ( !Directory.Exists( parquetFolder ) )
            {
                return new List<string>();
            }

            var actualDateRange = GetActualDateRange( dateRange );
            return Directory.EnumerateFiles( parquetFolder, "*.parquet", SearchOption.AllDirectories )
                .Where( f => !IsInTempFolder( f, parquetFolder ) )
                .Where( f => IsParquetFileInDateRange( f, actualDateRange ) )
                .OrderBy( f => f, StringComparer.OrdinalIgnoreCase )
                .Take( Math.Max( 1, maximumParquetFiles ) )
                .ToList();
        }

        public static SlidingDateRangeBag ToSlidingDateRangeBag( string delimitedDateRange )
        {
            if ( delimitedDateRange.IsNullOrWhiteSpace() )
            {
                return null;
            }

            var parts = delimitedDateRange.Split( '|' );
            if ( parts.Length != 5 )
            {
                return null;
            }

            SlidingDateRangeType rangeType;
            if ( !Enum.TryParse( parts[0], true, out rangeType ) )
            {
                return null;
            }

            TimeUnitType timeUnit;
            var hasTimeUnit = Enum.TryParse( parts[2], true, out timeUnit );
            return new SlidingDateRangeBag { RangeType = rangeType, TimeValue = parts[1].AsIntegerOrNull(), TimeUnit = hasTimeUnit ? timeUnit : ( TimeUnitType? ) null, LowerDate = parts[3].AsDateTime(), UpperDate = parts[4].AsDateTime() };
        }

        public static string ToDelimitedDateRange( SlidingDateRangeBag dateRange )
        {
            if ( dateRange == null )
            {
                return null;
            }

            return string.Format( "{0}|{1}|{2}|{3}|{4}", dateRange.RangeType, dateRange.TimeValue?.ToString() ?? string.Empty, dateRange.TimeUnit?.ToString() ?? string.Empty, dateRange.LowerDate?.ToString( "o" ) ?? string.Empty, dateRange.UpperDate?.ToString( "o" ) ?? string.Empty );
        }

        public static string ResolveParquetFolder( string configuredFolder )
        {
            if ( configuredFolder.IsNullOrWhiteSpace() )
            {
                configuredFolder = "IISLogParquet";
            }

            configuredFolder = Environment.ExpandEnvironmentVariables( configuredFolder );
            return Path.IsPathRooted( configuredFolder ) ? configuredFolder : Path.Combine( GetAppDataFolder(), configuredFolder );
        }

        private static string NormalizeQuery( string query )
        {
            query = ( query ?? string.Empty ).Trim();
            while ( query.EndsWith( ";" ) )
            {
                query = query.Substring( 0, query.Length - 1 ).Trim();
            }
            
            return query;
        }

        private static void AddSqlParameters( DuckDBCommand command, Dictionary<string, object> sqlParameters )
        {
            if ( sqlParameters == null || !sqlParameters.Any() )
            {
                return;
            }

            foreach ( var sqlParameter in sqlParameters )
            {
                var parameter = command.CreateParameter();
                parameter.ParameterName = sqlParameter.Key;
                parameter.Value = sqlParameter.Value ?? DBNull.Value;
                command.Parameters.Add( parameter );
            }
        }

        private void PopulateImpersonationTokenTable( DuckDBConnection connection, string rawLogsSql )
        {
            if ( rawLogsSql.IsNullOrWhiteSpace() )
            {
                return;
            }

            var impersonationUserNames = GetImpersonationUserNames( connection, rawLogsSql );
            foreach ( var userName in impersonationUserNames )
            {
                var personId = ResolveImpersonatedPersonId( userName );
                if ( !personId.HasValue )
                {
                    continue;
                }

                using ( var command = connection.CreateCommand() )
                {
                    command.CommandText = "INSERT INTO " + ImpersonationTokenTableName + " (cs_username, impersonated_person_id) VALUES ($cs_username, $impersonated_person_id)";

                    var userNameParameter = command.CreateParameter();
                    userNameParameter.ParameterName = "cs_username";
                    userNameParameter.Value = userName;
                    command.Parameters.Add( userNameParameter );

                    var personIdParameter = command.CreateParameter();
                    personIdParameter.ParameterName = "impersonated_person_id";
                    personIdParameter.Value = personId.Value;
                    command.Parameters.Add( personIdParameter );

                    command.ExecuteNonQuery();
                }
            }
        }

        protected virtual int? ResolveImpersonatedPersonId( string csUserName )
        {
            var impersonationToken = GetImpersonationToken( csUserName );
            if ( impersonationToken.IsNullOrWhiteSpace() )
            {
                return null;
            }

            using ( var rockContext = new RockContext() )
            {
                var personToken = new PersonTokenService( rockContext ).GetByImpersonationToken( impersonationToken );
                return personToken?.PersonAlias?.PersonId;
            }
        }

        private static List<string> GetImpersonationUserNames( DuckDBConnection connection, string rawLogsSql )
        {
            var userNames = new List<string>();
            using ( var command = connection.CreateCommand() )
            {
                command.CommandText = "SELECT DISTINCT \"cs-username\" FROM " + rawLogsSql + " __logs WHERE \"cs-username\" LIKE 'rckipid=%'";
                using ( var reader = command.ExecuteReader() )
                {
                    while ( reader.Read() )
                    {
                        if ( !reader.IsDBNull( 0 ) )
                        {
                            userNames.Add( reader.GetString( 0 ) );
                        }
                    }
                }
            }

            return userNames;
        }

        private static void CreateImpersonationTokenTable( DuckDBConnection connection )
        {
            using ( var command = connection.CreateCommand() )
            {
                command.CommandText = "CREATE TEMP TABLE " + ImpersonationTokenTableName + " (cs_username VARCHAR, impersonated_person_id INTEGER)";
                command.ExecuteNonQuery();
            }
        }

        private static string GetImpersonationToken( string csUserName )
        {
            const string prefix = "rckipid=";
            return csUserName != null && csUserName.StartsWith( prefix, StringComparison.OrdinalIgnoreCase )
                ? csUserName.Substring( prefix.Length )
                : null;
        }

        private static string GetRawLogsSql( string fileList )
        {
            return "( SELECT CAST(NULL AS BIGINT) AS \"sc-bytes\", CAST(NULL AS VARCHAR) AS \"cs-host\", CAST(NULL AS VARCHAR) AS \"cs-username\" WHERE 1 = 0 UNION ALL BY NAME SELECT * FROM read_parquet(" + fileList + ", union_by_name = true) )";
        }

        private static DataTable LoadDataTable( IDataReader reader )
        {
            var dataTable = new DataTable();
            var columnTypes = new List<Type>();
            for ( var i = 0; i < reader.FieldCount; i++ )
            {
                var fieldType = reader.GetFieldType( i );
                var columnType = fieldType == typeof( TimeSpan ) || fieldType?.Namespace == "DuckDB.NET.Native" ? typeof( string ) : fieldType ?? typeof( object );
                columnTypes.Add( columnType );
                dataTable.Columns.Add( reader.GetName( i ), columnType );
            }

            while ( reader.Read() )
            {
                var values = new object[reader.FieldCount];
                for ( var i = 0; i < reader.FieldCount; i++ )
                {
                    values[i] = reader.IsDBNull( i ) ? DBNull.Value : ConvertDuckDbValue( reader.GetValue( i ), columnTypes[i] );
                }

                dataTable.Rows.Add( values );
            }

            return dataTable;
        }

        private static object ConvertDuckDbValue( object value, Type targetType )
        {
            if ( value == null || value == DBNull.Value )
            {
                return DBNull.Value;
            }

            var duckDbNativeValue = ConvertDuckDbNativeValue( value );
            if ( duckDbNativeValue != null )
            {
                return duckDbNativeValue;
            }

            if ( targetType == typeof( string ) )
            {
                return value.ToString();
            }

            if ( targetType.IsInstanceOfType( value ) )
            {
                return value;
            }

            try
            {
                return Convert.ChangeType( value, targetType );
            }
            catch
            {
                return value.ToString();
            }
        }

        private static object ConvertDuckDbNativeValue( object value )
        {
            var valueType = value.GetType();
            if ( valueType.Namespace != "DuckDB.NET.Native" )
            {
                return null;
            }

            if ( valueType.Name == "DuckDBTimeOnly" )
            {
                var hour = ( byte ) valueType.GetProperty( "Hour" ).GetValue( value );
                var minute = ( byte ) valueType.GetProperty( "Min" ).GetValue( value );
                var second = ( byte ) valueType.GetProperty( "Sec" ).GetValue( value );
                var microsecond = ( int ) valueType.GetProperty( "Microsecond" ).GetValue( value );

                var time = string.Format( "{0:00}:{1:00}:{2:00}", hour, minute, second );
                return microsecond > 0
                    ? time + "." + microsecond.ToString( "000000" ).TrimEnd( '0' )
                    : time;
            }

            var toDateTimeMethod = valueType.GetMethod( "ToDateTime", Type.EmptyTypes );
            if ( toDateTimeMethod != null )
            {
                return ( ( DateTime ) toDateTimeMethod.Invoke( value, null ) ).ToString( "o" );
            }

            return value.ToString();
        }

        private static bool IsParquetFileInDateRange( string parquetFile, DateRange dateRange )
        {
            DateTime fileDate;
            if ( !TryGetDateFromParquetFileName( parquetFile, out fileDate ) )
            {
                return false;
            }

            return !( dateRange?.Start.HasValue == true && fileDate.Date < dateRange.Start.Value.Date ) && !( dateRange?.End.HasValue == true && fileDate.Date > dateRange.End.Value.Date );
        }

        private static DateRange GetActualDateRange( string dateRange )
        {
            dateRange = dateRange.IfEmpty( DefaultDateRange );
            var rangeType = dateRange.Split( '|' ).FirstOrDefault();
            if ( rangeType.Equals( "All", StringComparison.OrdinalIgnoreCase ) || rangeType == "-1" )
            {
                return null;
            }

            return Rock.Web.UI.Controls.SlidingDateRangePicker.CalculateDateRangeFromDelimitedValues( dateRange );
        }

        private static bool IsInTempFolder( string parquetFile, string parquetFolder )
        {
            var root = Path.GetFullPath( parquetFolder ).TrimEnd( Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar );
            var directory = Directory.GetParent( Path.GetFullPath( parquetFile ) );
            while ( directory != null && directory.FullName.StartsWith( root, StringComparison.OrdinalIgnoreCase ) )
            {
                if ( directory.FullName.Equals( root, StringComparison.OrdinalIgnoreCase ) )
                {
                    return false;
                }

                if ( directory.Name.Equals( "temp", StringComparison.OrdinalIgnoreCase ) )
                {
                    return true;
                }

                directory = directory.Parent;
            }

            return false;
        }

        private static bool TryGetDateFromParquetFileName( string parquetFile, out DateTime fileDate )
        {
            fileDate = default( DateTime );
            var match = Regex.Match( Path.GetFileNameWithoutExtension( parquetFile ) ?? string.Empty, @"^(?<date>\d{8})(?:_|$)" );
            return match.Success && DateTime.TryParseExact( match.Groups["date"].Value, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out fileDate );
        }

        private static string GetAppDataFolder()
        {
            var appDataFolder = HostingEnvironment.MapPath( "~/App_Data" );
            if ( appDataFolder.IsNullOrWhiteSpace() )
            {
                appDataFolder = AppDomain.CurrentDomain.GetData( "DataDirectory" ) as string;
            }

            return appDataFolder.IfEmpty( Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "App_Data" ) );
        }

        private static string EscapeSqlString( string value )
        {
            return value.Replace( "'", "''" );
        }

        private class PreparedQuery
        {
            public string Query { get; set; }

            public string RawLogsSql { get; set; }
        }
    }
}
