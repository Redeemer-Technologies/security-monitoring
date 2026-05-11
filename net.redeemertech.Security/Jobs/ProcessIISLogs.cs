using DuckDB.NET.Data;

using Quartz;

using Rock;
using Rock.Attribute;
using Rock.Jobs;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Hosting;
using System.Web.Script.Serialization;

namespace net.redeemertech.Security
{
    [DisplayName( "Process IIS Logs" )]
    [Description( "Converts IIS W3C logs to schema-specific parquet files in App_Data using DuckDB, processing only new log lines since the previous run." )]
    [TextField( "IIS Log Folder",
        "The IIS log folder to process. Leave blank to use %SystemDrive%\\inetpub\\logs\\LogFiles.",
        false,
        "",
        key: AttributeKey.IISLogFolder,
        order: 0 )]
    [TextField( "Parquet Folder",
        "The folder where parquet files and processing state should be stored. Relative paths are stored under App_Data.",
        true,
        "IISLogParquet",
        key: AttributeKey.ParquetFolder,
        order: 1 )]
    [IntegerField( "Retain Parquet Files For Days",
        "IIS log files last modified before this retention window will be skipped, and parquet files representing older log entries will be deleted each time the job runs.",
        true,
        730,
        key: AttributeKey.RetentionDays,
        order: 2 )]
    [BooleanField( "Re-process all files on next run",
        "Clears the saved processing state on the next job run so all IIS log files are processed again. The job turns this off after clearing the state.",
        false,
        key: AttributeKey.ReprocessAllFilesOnNextRun,
        order: 3 )]
    [DisallowConcurrentExecution]
    public class ProcessIISLogs : RockJob
    {
        private const string StateFileName = "iis-log-parquet-state.json";

        private static readonly Encoding Utf8NoBom = new UTF8Encoding( false );

        private class AttributeKey
        {
            public const string IISLogFolder = "IISLogFolder";
            public const string ParquetFolder = "ParquetFolder";
            public const string RetentionDays = "RetentionDays";
            public const string ReprocessAllFilesOnNextRun = "ReprocessAllFilesOnNextRun";
        }

        public override void Execute()
        {
            var inputFolder = ResolveIISLogFolder();
            if ( !Directory.Exists( inputFolder ) )
            {
                this.Result = string.Format( "IIS log folder does not exist: {0}", inputFolder );
                return;
            }

            var parquetFolder = ResolveParquetFolder();
            Directory.CreateDirectory( parquetFolder );
            Directory.CreateDirectory( GetTempFolder( parquetFolder ) );

            var retentionDays = Math.Max( 1, GetAttributeValue( AttributeKey.RetentionDays ).AsIntegerOrNull() ?? 90 );
            var cutoffUtc = DateTime.UtcNow.AddDays( -retentionDays );
            var statePath = Path.Combine( parquetFolder, StateFileName );
            var state = LoadState( statePath );
            var reprocessAllFiles = GetAttributeValue( AttributeKey.ReprocessAllFilesOnNextRun ).AsBoolean();
            if ( reprocessAllFiles )
            {
                state = new ProcessingState();
                ClearReprocessAllFilesOnNextRunAttribute();
            }

            var processedLogFiles = 0;
            var skippedLogFiles = 0;
            var expiredLogFiles = 0;
            var createdParquetFiles = 0;
            var processedRows = 0L;
            var deletedParquetFiles = 0;
            var compactedParquetFiles = 0;

            using ( var connection = new DuckDBConnection( "Data Source=:memory:" ) )
            {
                connection.Open();
                ExecuteDuckDbNonQuery( connection, "SET preserve_insertion_order = false" );

                foreach ( var logFilePath in Directory.EnumerateFiles( inputFolder, "*.log", SearchOption.AllDirectories ).OrderBy( f => f, StringComparer.OrdinalIgnoreCase ) )
                {
                    var fileInfo = new FileInfo( logFilePath );
                    if ( fileInfo.LastWriteTimeUtc < cutoffUtc )
                    {
                        expiredLogFiles++;
                        continue;
                    }

                    var fileState = state.GetFileState( logFilePath );
                    if ( !HasLogFileChanged( fileInfo, fileState ) )
                    {
                        skippedLogFiles++;
                        continue;
                    }

                    var fileResult = ProcessLogFile( connection, fileInfo, parquetFolder, fileState );
                    if ( fileResult.ProcessedAnyBytes )
                    {
                        processedLogFiles++;
                        createdParquetFiles += fileResult.CreatedParquetFiles;
                        processedRows += fileResult.ProcessedRows;
                        SaveState( statePath, state );
                    }
                }

                deletedParquetFiles = TrimExpiredParquetFiles( parquetFolder, retentionDays );
                compactedParquetFiles = CompactPriorDayParquetFiles( connection, parquetFolder );
            }

            CleanupTempFolder( parquetFolder );
            SaveState( statePath, state );

            this.Result = string.Format(
                "Processed {0:N0} rows from {1:N0} IIS log files. Skipped {2:N0} unchanged IIS log files and {3:N0} expired IIS log files. Created {4:N0} parquet files, compacted {5:N0} prior-day parquet files, and deleted {6:N0} expired parquet files.",
                processedRows,
                processedLogFiles,
                skippedLogFiles,
                expiredLogFiles,
                createdParquetFiles,
                compactedParquetFiles,
                deletedParquetFiles );
        }

        private ProcessingResult ProcessLogFile( DuckDBConnection connection, FileInfo fileInfo, string parquetFolder, LogFileState fileState )
        {
            var logFilePath = fileInfo.FullName;
            if ( fileInfo.Length < fileState.Offset )
            {
                fileState.Offset = 0;
                fileState.Fields = new List<string>();
            }

            var batches = ExtractNewLogBatches( logFilePath, parquetFolder, fileState );
            var sourceHash = GetSourceHash( fileInfo.FullName );
            var result = new ProcessingResult
            {
                ProcessedAnyBytes = batches.ProcessedAnyBytes,
                ProcessedRows = batches.TotalRows
            };

            foreach ( var batch in batches.Batches )
            {
                try
                {
                    ConvertBatchToParquet( connection, batch, fileInfo, parquetFolder, sourceHash );
                    result.CreatedParquetFiles++;
                }
                finally
                {
                    DeleteFileIfExists( batch.TempCsvPath );
                }
            }

            fileState.Offset = batches.FinalOffset;
            fileState.Fields = batches.CurrentFields;
            fileState.LastProcessedUtc = DateTime.UtcNow;
            fileState.LastKnownLength = fileInfo.Length;
            fileState.LastKnownWriteTimeUtc = fileInfo.LastWriteTimeUtc;

            return result;
        }

        private static bool HasLogFileChanged( FileInfo fileInfo, LogFileState fileState )
        {
            return fileState.LastKnownWriteTimeUtc == default( DateTime )
                || fileInfo.LastWriteTimeUtc != fileState.LastKnownWriteTimeUtc
                || fileInfo.Length != fileState.LastKnownLength;
        }

        private ExtractedBatches ExtractNewLogBatches( string logFilePath, string parquetFolder, LogFileState fileState )
        {
            var result = new ExtractedBatches
            {
                FinalOffset = fileState.Offset,
                CurrentFields = fileState.Fields == null ? new List<string>() : new List<string>( fileState.Fields )
            };

            LogBatch currentBatch = null;
            StreamWriter currentWriter = null;

            try
            {
                using ( var stream = new FileStream( logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 1024 ) )
                {
                    stream.Seek( fileState.Offset, SeekOrigin.Begin );

                    foreach ( var logLine in ReadCompleteLines( stream ) )
                    {
                        result.ProcessedAnyBytes = true;
                        result.FinalOffset = logLine.NextOffset;

                        List<string> fields;
                        if ( TryParseFieldsLine( logLine.Text, out fields ) )
                        {
                            CloseBatch( currentWriter );
                            currentWriter = null;
                            currentBatch = null;
                            result.CurrentFields = fields;
                            continue;
                        }

                        if ( logLine.Text.Length == 0 || logLine.Text[0] == '#' || result.CurrentFields == null || result.CurrentFields.Count == 0 )
                        {
                            continue;
                        }

                        if ( currentBatch == null )
                        {
                            CloseBatch( currentWriter );
                            currentBatch = CreateBatch( parquetFolder, result.CurrentFields, logLine.StartOffset );
                            currentWriter = new StreamWriter( currentBatch.TempCsvPath, false, Utf8NoBom, 1024 * 1024 );
                            result.Batches.Add( currentBatch );
                        }

                        currentWriter.WriteLine( logLine.Text );
                        currentBatch.RowCount++;
                        currentBatch.EndOffset = logLine.NextOffset;
                        UpdateLatestEntryDate( currentBatch, logLine.Text );
                        result.TotalRows++;
                    }
                }
            }
            finally
            {
                CloseBatch( currentWriter );
            }

            result.Batches.RemoveAll( b =>
            {
                if ( b.RowCount > 0 )
                {
                    return false;
                }

                DeleteFileIfExists( b.TempCsvPath );
                return true;
            } );

            return result;
        }

        private static IEnumerable<LogLine> ReadCompleteLines( FileStream stream )
        {
            var buffer = new byte[64 * 1024];
            var lineBytes = new List<byte>( 512 );
            var lineStartOffset = stream.Position;

            while ( true )
            {
                var bufferStartOffset = stream.Position;
                var bytesRead = stream.Read( buffer, 0, buffer.Length );
                if ( bytesRead == 0 )
                {
                    yield break;
                }

                for ( var i = 0; i < bytesRead; i++ )
                {
                    var currentByte = buffer[i];
                    if ( currentByte == '\n' )
                    {
                        if ( lineBytes.Count > 0 && lineBytes[lineBytes.Count - 1] == '\r' )
                        {
                            lineBytes.RemoveAt( lineBytes.Count - 1 );
                        }

                        var nextOffset = bufferStartOffset + i + 1;
                        yield return new LogLine
                        {
                            Text = Utf8NoBom.GetString( lineBytes.ToArray() ),
                            StartOffset = lineStartOffset,
                            NextOffset = nextOffset
                        };

                        lineBytes.Clear();
                        lineStartOffset = nextOffset;
                    }
                    else
                    {
                        lineBytes.Add( currentByte );
                    }
                }
            }
        }

        private static bool TryParseFieldsLine( string line, out List<string> fields )
        {
            const string fieldsPrefix = "#Fields:";
            const string spacedFieldsPrefix = "# Fields:";
            fields = null;

            string fieldsText;
            if ( line.StartsWith( fieldsPrefix, StringComparison.OrdinalIgnoreCase ) )
            {
                fieldsText = line.Substring( fieldsPrefix.Length );
            }
            else if ( line.StartsWith( spacedFieldsPrefix, StringComparison.OrdinalIgnoreCase ) )
            {
                fieldsText = line.Substring( spacedFieldsPrefix.Length );
            }
            else
            {
                return false;
            }

            fields = fieldsText.Split( new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries ).ToList();
            return fields.Count > 0;
        }

        private LogBatch CreateBatch( string parquetFolder, List<string> fields, long startOffset )
        {
            var schema = CreateSchema( fields );
            var tempFolder = GetTempFolder( parquetFolder );
            Directory.CreateDirectory( tempFolder );

            return new LogBatch
            {
                Fields = new List<string>( fields ),
                Columns = schema.Columns,
                SchemaHash = schema.Hash,
                DateFieldIndex = fields.FindIndex( f => f.Equals( "date", StringComparison.OrdinalIgnoreCase ) ),
                StartOffset = startOffset,
                TempCsvPath = Path.Combine( tempFolder, Guid.NewGuid().ToString( "N" ) + ".log" )
            };
        }

        private static void UpdateLatestEntryDate( LogBatch batch, string line )
        {
            if ( batch.DateFieldIndex < 0 )
            {
                return;
            }

            var values = line.Split( new[] { ' ' }, StringSplitOptions.None );
            if ( batch.DateFieldIndex >= values.Length )
            {
                return;
            }

            DateTime entryDate;
            if ( !DateTime.TryParseExact( values[batch.DateFieldIndex], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out entryDate ) )
            {
                return;
            }

            if ( !batch.LatestEntryDate.HasValue || entryDate > batch.LatestEntryDate.Value )
            {
                batch.LatestEntryDate = entryDate;
            }
        }

        private void ConvertBatchToParquet( DuckDBConnection connection, LogBatch batch, FileInfo fileInfo, string parquetFolder, string sourceHash )
        {
            var schemaFolder = GetSchemaFolder( parquetFolder, batch.SchemaHash );
            Directory.CreateDirectory( schemaFolder );

            var representedDate = ( batch.LatestEntryDate ?? fileInfo.LastWriteTimeUtc.Date ).Date;
            var sourceName = SanitizeFileName( Path.GetFileNameWithoutExtension( fileInfo.Name ) );

            var outputPath = Path.Combine(
                schemaFolder,
                string.Format(
                    "{0:yyyyMMdd}_{1}_{2}_{3}_{4}_{5}.parquet",
                    representedDate,
                    sourceName,
                    sourceHash,
                    batch.SchemaHash,
                    batch.StartOffset,
                    batch.EndOffset ) );

            var tempOutputPath = Path.Combine( GetTempFolder( parquetFolder ), Guid.NewGuid().ToString( "N" ) + ".tmp" );

            var columnsSql = string.Join( ", ", batch.Columns.Select( c => string.Format( "'{0}':'{1}'", EscapeSqlString( c.Name ), c.DuckDbType ) ) );
            var sql = string.Format(
                "COPY (SELECT * FROM read_csv('{0}', delim = ' ', header = false, columns = {{{1}}}, nullstr = '-', quote = '', escape = '', ignore_errors = true, sample_size = -1)) TO '{2}' (FORMAT PARQUET, COMPRESSION ZSTD)",
                EscapeSqlString( batch.TempCsvPath ),
                columnsSql,
                EscapeSqlString( tempOutputPath ) );

            ExecuteDuckDbNonQuery( connection, sql );
            DeleteFileIfExists( outputPath );
            File.Move( tempOutputPath, outputPath );
            File.SetLastWriteTimeUtc( outputPath, DateTime.SpecifyKind( representedDate, DateTimeKind.Utc ) );
        }

        private int CompactPriorDayParquetFiles( DuckDBConnection connection, string parquetFolder )
        {
            var schemasFolder = Path.Combine( parquetFolder, "schemas" );
            if ( !Directory.Exists( schemasFolder ) )
            {
                return 0;
            }

            var todayUtc = DateTime.UtcNow.Date;
            var compactedFiles = 0;

            foreach ( var schemaFolder in Directory.EnumerateDirectories( schemasFolder ) )
            {
                var schemaHash = Path.GetFileName( schemaFolder );
                var parquetFilesByDate = Directory.EnumerateFiles( schemaFolder, "*.parquet", SearchOption.TopDirectoryOnly )
                    .Select( f => new
                    {
                        Path = f,
                        RepresentedDate = GetRepresentedDateFromParquetFileName( f )
                    } )
                    .Where( f => f.RepresentedDate.HasValue && f.RepresentedDate.Value.Date < todayUtc )
                    .GroupBy( f => f.RepresentedDate.Value.Date )
                    .ToList();

                foreach ( var dateGroup in parquetFilesByDate )
                {
                    var sourceFiles = dateGroup.Select( f => f.Path ).OrderBy( f => f, StringComparer.OrdinalIgnoreCase ).ToList();
                    if ( sourceFiles.Count < 2 )
                    {
                        continue;
                    }

                    CompactParquetFilesForDate( connection, parquetFolder, schemaFolder, schemaHash, dateGroup.Key, sourceFiles );
                    compactedFiles += sourceFiles.Count;
                }
            }

            return compactedFiles;
        }

        private void CompactParquetFilesForDate( DuckDBConnection connection, string parquetFolder, string schemaFolder, string schemaHash, DateTime representedDate, List<string> sourceFiles )
        {
            var tempOutputPath = Path.Combine( GetTempFolder( parquetFolder ), Guid.NewGuid().ToString( "N" ) + ".tmp" );
            var outputPath = Path.Combine( schemaFolder, string.Format( "{0:yyyyMMdd}_compacted_{1}.parquet", representedDate, schemaHash ) );
            var parquetListSql = "[" + string.Join( ",", sourceFiles.Select( f => "'" + EscapeSqlString( f ) + "'" ) ) + "]";
            var sql = string.Format(
                "COPY (SELECT * FROM read_parquet({0}, union_by_name = false)) TO '{1}' (FORMAT PARQUET, COMPRESSION ZSTD)",
                parquetListSql,
                EscapeSqlString( tempOutputPath ) );

            ExecuteDuckDbNonQuery( connection, sql );

            foreach ( var sourceFile in sourceFiles )
            {
                DeleteFileIfExists( sourceFile );
            }

            DeleteFileIfExists( outputPath );
            File.Move( tempOutputPath, outputPath );
            File.SetLastWriteTimeUtc( outputPath, DateTime.SpecifyKind( representedDate.Date, DateTimeKind.Utc ) );
        }

        private int TrimExpiredParquetFiles( string parquetFolder, int retentionDays )
        {
            var cutoffUtc = DateTime.UtcNow.AddDays( -retentionDays );
            var deletedFiles = 0;

            foreach ( var parquetFile in Directory.EnumerateFiles( parquetFolder, "*.parquet", SearchOption.AllDirectories ) )
            {
                var fileInfo = new FileInfo( parquetFile );
                DateTime representedDate;
                if ( TryGetRepresentedDateFromParquetFileName( parquetFile, out representedDate ) )
                {
                    if ( representedDate >= cutoffUtc.Date )
                    {
                        continue;
                    }

                    DeleteFileIfExists( parquetFile );
                    deletedFiles++;
                    continue;
                }

                if ( fileInfo.LastWriteTimeUtc >= cutoffUtc )
                {
                    continue;
                }

                DeleteFileIfExists( parquetFile );
                deletedFiles++;
            }

            return deletedFiles;
        }

        private static bool TryGetRepresentedDateFromParquetFileName( string parquetFile, out DateTime representedDate )
        {
            var parsedDate = GetRepresentedDateFromParquetFileName( parquetFile );
            representedDate = parsedDate ?? default( DateTime );
            return parsedDate.HasValue;
        }

        private static DateTime? GetRepresentedDateFromParquetFileName( string parquetFile )
        {
            var fileName = Path.GetFileNameWithoutExtension( parquetFile );
            if ( fileName.IsNullOrWhiteSpace() || fileName.Length < 8 )
            {
                return null;
            }

            DateTime representedDate;
            if ( !DateTime.TryParseExact( fileName.Substring( 0, 8 ), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out representedDate ) )
            {
                return null;
            }

            return representedDate;
        }

        private static SchemaInfo CreateSchema( List<string> fields )
        {
            var columns = fields.Select( f => new SchemaColumn
            {
                Name = f,
                DuckDbType = GetDuckDbType( f )
            } ).ToList();

            return new SchemaInfo
            {
                Columns = columns,
                Hash = HashString( string.Join( "\n", columns.Select( c => c.Name + ":" + c.DuckDbType ) ) ).Substring( 0, 16 )
            };
        }

        private static string GetDuckDbType( string fieldName )
        {
            switch ( fieldName.ToLowerInvariant() )
            {
                case "date":
                    return "DATE";
                case "time":
                    return "TIME";
                case "s-port":
                case "c-port":
                case "sc-status":
                case "sc-substatus":
                case "sc-win32-status":
                case "time-taken":
                    return "INTEGER";
                case "cs-bytes":
                case "sc-bytes":
                    return "BIGINT";
                default:
                    return "VARCHAR";
            }
        }

        private string ResolveIISLogFolder()
        {
            var configuredFolder = GetAttributeValue( AttributeKey.IISLogFolder );
            if ( configuredFolder.IsNotNullOrWhiteSpace() )
            {
                return Environment.ExpandEnvironmentVariables( configuredFolder );
            }

            var systemDrive = Environment.GetEnvironmentVariable( "SystemDrive" );
            if ( systemDrive.IsNullOrWhiteSpace() )
            {
                systemDrive = Path.GetPathRoot( Environment.SystemDirectory );
            }

            if ( systemDrive.IsNullOrWhiteSpace() )
            {
                systemDrive = @"C:\";
            }

            return Path.Combine( systemDrive.TrimEnd( Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar ) + Path.DirectorySeparatorChar, "inetpub", "logs", "LogFiles" );
        }

        private string ResolveParquetFolder()
        {
            var configuredFolder = GetAttributeValue( AttributeKey.ParquetFolder );
            if ( configuredFolder.IsNullOrWhiteSpace() )
            {
                configuredFolder = "IISLogParquet";
            }

            configuredFolder = Environment.ExpandEnvironmentVariables( configuredFolder );
            if ( Path.IsPathRooted( configuredFolder ) )
            {
                return configuredFolder;
            }

            return Path.Combine( GetAppDataFolder(), configuredFolder );
        }

        private static string GetAppDataFolder()
        {
            var appDataFolder = HostingEnvironment.MapPath( "~/App_Data" );
            if ( appDataFolder.IsNullOrWhiteSpace() )
            {
                var dataDirectory = AppDomain.CurrentDomain.GetData( "DataDirectory" ) as string;
                if ( dataDirectory.IsNotNullOrWhiteSpace() )
                {
                    appDataFolder = dataDirectory;
                }
            }

            if ( appDataFolder.IsNullOrWhiteSpace() )
            {
                appDataFolder = Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "App_Data" );
            }

            Directory.CreateDirectory( appDataFolder );
            return appDataFolder;
        }

        private static string GetSchemaFolder( string parquetFolder, string schemaHash )
        {
            return Path.Combine( parquetFolder, "schemas", schemaHash );
        }

        private static string GetTempFolder( string parquetFolder )
        {
            return Path.Combine( parquetFolder, "temp" );
        }

        private static void CleanupTempFolder( string parquetFolder )
        {
            var tempFolder = GetTempFolder( parquetFolder );
            if ( !Directory.Exists( tempFolder ) )
            {
                return;
            }

            foreach ( var file in Directory.EnumerateFiles( tempFolder ) )
            {
                DeleteFileIfExists( file );
            }
        }

        private static ProcessingState LoadState( string statePath )
        {
            if ( !File.Exists( statePath ) )
            {
                return new ProcessingState();
            }

            var serializer = new JavaScriptSerializer
            {
                MaxJsonLength = int.MaxValue
            };
            var json = File.ReadAllText( statePath );
            return serializer.Deserialize<ProcessingState>( json ) ?? new ProcessingState();
        }

        private static void SaveState( string statePath, ProcessingState state )
        {
            var serializer = new JavaScriptSerializer
            {
                MaxJsonLength = int.MaxValue
            };
            var json = serializer.Serialize( state );
            File.WriteAllText( statePath, json, Utf8NoBom );
        }

        private void ClearReprocessAllFilesOnNextRunAttribute()
        {
            if ( ServiceJob == null )
            {
                return;
            }

            ServiceJob.SetAttributeValue( AttributeKey.ReprocessAllFilesOnNextRun, "False" );
            ServiceJob.SaveAttributeValue( AttributeKey.ReprocessAllFilesOnNextRun );
        }

        private static void ExecuteDuckDbNonQuery( DuckDBConnection connection, string sql )
        {
            using ( var command = connection.CreateCommand() )
            {
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
        }

        private static void CloseBatch( StreamWriter writer )
        {
            if ( writer != null )
            {
                writer.Dispose();
            }
        }

        private static void DeleteFileIfExists( string path )
        {
            if ( File.Exists( path ) )
            {
                File.Delete( path );
            }
        }

        private static string EscapeSqlString( string value )
        {
            return value.Replace( "\\", "\\\\" ).Replace( "'", "''" );
        }

        private static string SanitizeFileName( string value )
        {
            if ( value.IsNullOrWhiteSpace() )
            {
                return "log";
            }

            foreach ( var invalidChar in Path.GetInvalidFileNameChars() )
            {
                value = value.Replace( invalidChar, '_' );
            }

            return value;
        }

        private static string GetSourceHash( string logFilePath )
        {
            return HashString( logFilePath ).Substring( 0, 12 );
        }

        private static string HashString( string value )
        {
            using ( var sha256 = SHA256.Create() )
            {
                var bytes = sha256.ComputeHash( Utf8NoBom.GetBytes( value ?? string.Empty ) );
                return BitConverter.ToString( bytes ).Replace( "-", string.Empty ).ToLowerInvariant();
            }
        }

        private class ProcessingResult
        {
            public bool ProcessedAnyBytes { get; set; }

            public long ProcessedRows { get; set; }

            public int CreatedParquetFiles { get; set; }
        }

        public class ProcessingState
        {
            public ProcessingState()
            {
                Files = new List<LogFileState>();
            }

            public List<LogFileState> Files { get; set; }

            public LogFileState GetFileState( string path )
            {
                if ( Files == null )
                {
                    Files = new List<LogFileState>();
                }

                var normalizedPath = path.ToUpperInvariant();
                var fileState = Files.FirstOrDefault( f => f.PathKey == normalizedPath );
                if ( fileState == null )
                {
                    fileState = new LogFileState
                    {
                        Path = path,
                        PathKey = normalizedPath,
                        Fields = new List<string>()
                    };
                    Files.Add( fileState );
                }

                return fileState;
            }
        }

        public class LogFileState
        {
            public string Path { get; set; }

            public string PathKey { get; set; }

            public long Offset { get; set; }

            public long LastKnownLength { get; set; }

            public DateTime LastKnownWriteTimeUtc { get; set; }

            public DateTime LastProcessedUtc { get; set; }

            public List<string> Fields { get; set; }
        }

        private class ExtractedBatches
        {
            public ExtractedBatches()
            {
                Batches = new List<LogBatch>();
                CurrentFields = new List<string>();
            }

            public List<LogBatch> Batches { get; set; }

            public bool ProcessedAnyBytes { get; set; }

            public long FinalOffset { get; set; }

            public long TotalRows { get; set; }

            public List<string> CurrentFields { get; set; }
        }

        private class LogBatch
        {
            public List<string> Fields { get; set; }

            public List<SchemaColumn> Columns { get; set; }

            public string SchemaHash { get; set; }

            public int DateFieldIndex { get; set; }

            public DateTime? LatestEntryDate { get; set; }

            public string TempCsvPath { get; set; }

            public long StartOffset { get; set; }

            public long EndOffset { get; set; }

            public int RowCount { get; set; }
        }

        private class SchemaInfo
        {
            public List<SchemaColumn> Columns { get; set; }

            public string Hash { get; set; }
        }

        private class SchemaColumn
        {
            public string Name { get; set; }

            public string DuckDbType { get; set; }
        }

        private class LogLine
        {
            public string Text { get; set; }

            public long StartOffset { get; set; }

            public long NextOffset { get; set; }
        }
    }
}
