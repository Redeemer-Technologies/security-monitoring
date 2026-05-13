using DuckDB.NET.Data;

using Rock;
using Rock.Enums.Controls;
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

        public DataTable Execute( string query, string dateRange, string parquetFolder, int maximumParquetFiles, int timeoutSeconds )
        {
            var preparedQuery = PrepareQuery( query, dateRange, parquetFolder, maximumParquetFiles );

            using ( var connection = new DuckDBConnection( "Data Source=:memory:" ) )
            {
                connection.Open();
                using ( var command = connection.CreateCommand() )
                {
                    command.CommandText = preparedQuery;
                    command.CommandTimeout = timeoutSeconds;

                    using ( var reader = command.ExecuteReader() )
                    {
                        return LoadDataTable( reader );
                    }
                }
            }
        }

        public string PrepareQuery( string query, string dateRange, string parquetFolder, int maximumParquetFiles )
        {
            query = NormalizeQuery( query );
            if ( !query.Contains( LogsPlaceholder ) )
            {
                throw new InvalidOperationException( "The query must include [[logs]] as the placeholder for the IIS log parquet source." );
            }

            var placeholderCount = Regex.Matches(query, Regex.Escape(LogsPlaceholder)).Count;
            if (placeholderCount != 1)
            {
                throw new InvalidOperationException("The query must include [[logs]] exactly once.");
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
            var logsFromSql = "( SELECT CAST(NULL AS BIGINT) AS \"sc-bytes\", CAST(NULL AS VARCHAR) AS \"cs-host\" WHERE 1 = 0 UNION ALL BY NAME SELECT * FROM read_parquet(" + fileList + ", union_by_name = true) )";
            return query.Replace( LogsPlaceholder, logsFromSql );
        }

        public List<string> GetParquetFiles( string dateRange, string parquetFolder, int maximumParquetFiles )
        {
            parquetFolder = ResolveParquetFolder( parquetFolder );
            if ( !Directory.Exists( parquetFolder ) )
            {
                return new List<string>();
            }

            var actualDateRange = Rock.Web.UI.Controls.SlidingDateRangePicker.CalculateDateRangeFromDelimitedValues( dateRange.IfEmpty( DefaultDateRange ) );
            return Directory.EnumerateFiles( parquetFolder, "*.parquet", SearchOption.AllDirectories )
                .Where( f => f.IndexOf( Path.DirectorySeparatorChar + "temp" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase ) < 0 )
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

            if ( value.GetType().Namespace == "DuckDB.NET.Native" || targetType == typeof( string ) )
            {
                return value.ToString();
            }

            return targetType.IsInstanceOfType( value ) ? value : value.ToString();
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
    }
}
