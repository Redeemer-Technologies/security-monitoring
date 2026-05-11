using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

using Rock;
using Rock.Plugin;
using Rock.Security;
using Rock.Model;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber(2, "1.17.0")]
    class Jobs : Migration
    {
        private const string ProcessIISLogsJobGuid = "f26fd3d5-32fa-4400-992a-f979dd4c36b5";
        private const string SecurityAuditJobGuid = "637dba19-b809-420e-ba66-864a03c46484";

        public override void Up()
        {
            AddOrUpdateServiceJob(
                ProcessIISLogsJobGuid,
                "Process IIS Logs",
                "Converts IIS W3C logs to schema-specific parquet files in App_Data using DuckDB, processing only new log lines since the previous run.",
                "net.redeemertech.Security.ProcessIISLogs",
                "0 0/5 * 1/1 * ? *" );

            AddOrUpdateServiceJob(
                SecurityAuditJobGuid,
                "Security Audit",
                "Audits Rock security settings, security role membership, binary file type view permissions, and document type view permissions.",
                "net.redeemertech.Security.SecurityAudit",
                "0 0 0 1/1 * ? *" );
        }

        public override void Down()
        {
            Sql( $@"
                DELETE FROM [ServiceJob]
                WHERE [Guid] IN ('{ProcessIISLogsJobGuid}', '{SecurityAuditJobGuid}')" );
        }

        private void AddOrUpdateServiceJob( string guid, string name, string description, string jobClass, string cronExpression )
        {
            Sql( $@"
                DECLARE @JobId int = (
                    SELECT TOP 1 [Id]
                    FROM [ServiceJob]
                    WHERE [Guid] = '{guid}' OR [Class] = '{jobClass}'
                    ORDER BY CASE WHEN [Guid] = '{guid}' THEN 0 ELSE 1 END
                );

                IF @JobId IS NULL
                BEGIN
                    INSERT INTO [ServiceJob] (
                          [IsSystem]
                        , [IsActive]
                        , [Name]
                        , [Description]
                        , [Class]
                        , [CronExpression]
                        , [NotificationStatus]
                        , [Guid]
                    ) VALUES (
                          0
                        , 1
                        , '{name}'
                        , '{description}'
                        , '{jobClass}'
                        , '{cronExpression}'
                        , 4
                        , '{guid}'
                    );
                END
                ELSE
                BEGIN
                    UPDATE [ServiceJob]
                    SET [IsActive] = 1
                        , [Name] = '{name}'
                        , [Description] = '{description}'
                        , [Class] = '{jobClass}'
                        , [CronExpression] = '{cronExpression}'
                    WHERE [Id] = @JobId;
                END" );

        }
    }
}
