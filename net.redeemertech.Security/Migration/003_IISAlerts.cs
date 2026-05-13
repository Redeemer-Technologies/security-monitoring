using Rock;
using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 3, "1.17.0" )]
    public class IISAlerts : Migration
    {
        private const string ProcessIISAlertsJobGuid = "05cb25eb-1faa-4553-8799-e3a068f042d8";
        private const string IISAlertTriggeredSystemCommunicationGuid = "94fbe63b-5e70-4332-898a-d8031512dc82";
        private const string ProcessIISAlertsAlertEmailAttributeGuid = "bf8e3170-4996-4754-a31d-74aac21cf1dd";
        public override void Up()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_IISAlert]', N'U') IS NULL
                BEGIN
                    CREATE TABLE [dbo].[_net_redeemertech_IISAlert] (
                        [Id] [int] IDENTITY(1,1) NOT NULL,
                        [Name] [nvarchar](100) NOT NULL,
                        [Description] [nvarchar](max) NULL,
                        [IsActive] [bit] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_IsActive] DEFAULT ((1)),
                        [Query] [nvarchar](max) NOT NULL,
                        [SummaryLava] [nvarchar](max) NULL,
                        [DateRange] [nvarchar](100) NULL,
                        [NotificationEmails] [nvarchar](max) NULL,
                        [EvaluationFrequencyMinutes] [int] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_EvaluationFrequencyMinutes] DEFAULT ((60)),
                        [LastRunDateTime] [datetime] NULL,
                        [CreatedDateTime] [datetime] NULL,
                        [ModifiedDateTime] [datetime] NULL,
                        [CreatedByPersonAliasId] [int] NULL,
                        [ModifiedByPersonAliasId] [int] NULL,
                        [Guid] [uniqueidentifier] NOT NULL,
                        [ForeignId] [int] NULL,
                        [ForeignGuid] [uniqueidentifier] NULL,
                        [ForeignKey] [nvarchar](100) NULL,
                        CONSTRAINT [PK__net_redeemertech_IISAlert] PRIMARY KEY CLUSTERED ([Id] ASC)
                    );
                    CREATE UNIQUE NONCLUSTERED INDEX [IX__net_redeemertech_IISAlert_Guid] ON [dbo].[_net_redeemertech_IISAlert] ([Guid] ASC);
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_IISAlertHistory]', N'U') IS NULL
                BEGIN
                    CREATE TABLE [dbo].[_net_redeemertech_IISAlertHistory] (
                        [Id] [int] IDENTITY(1,1) NOT NULL,
                        [IISAlertId] [int] NOT NULL,
                        [AlertName] [nvarchar](100) NOT NULL,
                        [TrippedDateTime] [datetime] NOT NULL,
                        [ResultCount] [int] NOT NULL,
                        [Summary] [nvarchar](max) NULL,
                        [ResultJson] [nvarchar](max) NULL,
                        [CreatedDateTime] [datetime] NULL,
                        [ModifiedDateTime] [datetime] NULL,
                        [CreatedByPersonAliasId] [int] NULL,
                        [ModifiedByPersonAliasId] [int] NULL,
                        [Guid] [uniqueidentifier] NOT NULL,
                        [ForeignId] [int] NULL,
                        [ForeignGuid] [uniqueidentifier] NULL,
                        [ForeignKey] [nvarchar](100) NULL,
                        CONSTRAINT [PK__net_redeemertech_IISAlertHistory] PRIMARY KEY CLUSTERED ([Id] ASC),
                        CONSTRAINT [FK__net_redeemertech_IISAlertHistory_IISAlert] FOREIGN KEY ([IISAlertId]) REFERENCES [dbo].[_net_redeemertech_IISAlert] ([Id]) ON DELETE CASCADE
                    );
                    CREATE UNIQUE NONCLUSTERED INDEX [IX__net_redeemertech_IISAlertHistory_Guid] ON [dbo].[_net_redeemertech_IISAlertHistory] ([Guid] ASC);
                    CREATE NONCLUSTERED INDEX [IX__net_redeemertech_IISAlertHistory_IISAlertId_TrippedDateTime] ON [dbo].[_net_redeemertech_IISAlertHistory] ([IISAlertId] ASC, [TrippedDateTime] DESC);
                END" );

            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Model.IISAlert", "IIS Alert", "net.redeemertech.Security.Model.IISAlert, net.redeemertech.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "590c8327-928e-4edb-8427-3d816d5b50ec");
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Model.IISAlertHistory", "IIS Alert History", "net.redeemertech.Security.Model.IISAlertHistory, net.redeemertech.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "acd20dc2-8ac2-4b65-90b3-5fd3f99cd0dd");

            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Blocks.Blocks.IISAlertList", "IIS Alert List", "net.redeemertech.Security.Blocks.Blocks.IISAlertList, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "1eb38156-8e6e-4d62-b7a0-6a3313b938b1");
            RockMigrationHelper.AddOrUpdateEntityBlockType( "IIS Alert List", "Lists IIS alerts and links to the alert detail block.", "net.redeemertech.Security.Blocks.Blocks.IISAlertList", "net_redeemertech > Security", "49531c16-1f93-49d9-bcab-9e7fd889e1bf");
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Blocks.Blocks.IISAlertDetail", "IIS Alert Detail", "net.redeemertech.Security.Blocks.Blocks.IISAlertDetail, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "2069f66c-9dac-4250-a694-521e463adb4a");
            RockMigrationHelper.AddOrUpdateEntityBlockType( "IIS Alert Detail", "Edits a single IIS alert.", "net.redeemertech.Security.Blocks.Blocks.IISAlertDetail", "net_redeemertech > Security", "c8032b08-fc23-479d-90d3-9ddf049a6a3c");
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Blocks.Blocks.IISAlertHistoryList", "IIS Alert History List", "net.redeemertech.Security.Blocks.Blocks.IISAlertHistoryList, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "e7c4771f-c705-4632-8ffd-78084f2ca195");
            RockMigrationHelper.AddOrUpdateEntityBlockType( "IIS Alert History List", "Lists tripped IIS alert history records.", "net.redeemertech.Security.Blocks.Blocks.IISAlertHistoryList", "net_redeemertech > Security", "655ca478-fdcf-4996-901c-6011b485e52b");
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Blocks.Blocks.IISAlertHistoryDetail", "IIS Alert History Detail", "net.redeemertech.Security.Blocks.Blocks.IISAlertHistoryDetail, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "d63b58d3-a198-4058-894a-2cb961ff0e1c");
            RockMigrationHelper.AddOrUpdateEntityBlockType( "IIS Alert History Detail", "Displays a single tripped IIS alert history record.", "net.redeemertech.Security.Blocks.Blocks.IISAlertHistoryDetail", "net_redeemertech > Security", "da59b549-4345-408c-b5f7-5680328b46e7");

            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("49531c16-1f93-49d9-bcab-9e7fd889e1bf", Rock.SystemGuid.FieldType.PAGE_REFERENCE, "Detail Page", "DetailPage", "Detail Page", @"Page containing the IIS Alert Detail block.", 0, @"", "fed8baec-1758-4dfa-84f2-c394c8f34616" );
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("655ca478-fdcf-4996-901c-6011b485e52b", Rock.SystemGuid.FieldType.PAGE_REFERENCE, "Detail Page", "DetailPage", "Detail Page", @"Page containing the IIS Alert History Detail block.", 0, @"", "2ae8485c-0589-4c6b-9bd4-0cb24e613c64" );


            AddOrUpdateServiceJob(
                ProcessIISAlertsJobGuid,
                "Process IIS Alerts",
                "Evaluates active IIS alerts against processed IIS log parquet files and emails configured recipients when an alert trips.",
                "net.redeemertech.Security.ProcessIISAlerts",
                "0 0/5 * 1/1 * ? *");

            RockMigrationHelper.AddOrUpdateEntityAttribute("Rock.Model.ServiceJob", Rock.SystemGuid.FieldType.TEXT, "Class", "net.redeemertech.Security.ProcessIISAlerts", "Parquet Folder", "Parquet Folder", @"The folder containing parquet files created by Process IIS Logs. Relative paths are resolved under App_Data.", 0, @"IISLogParquet", "111850d7-3f83-4b83-8f3a-27e8c75ea08b", "ParquetFolder");
            RockMigrationHelper.AddOrUpdateEntityAttribute("Rock.Model.ServiceJob", Rock.SystemGuid.FieldType.INTEGER, "Class", "net.redeemertech.Security.ProcessIISAlerts", "Maximum Parquet Files", "Maximum Parquet Files", @"The maximum number of parquet files to include in each alert query.", 1, @"1000", "35ed9fcb-78a2-4dee-9635-e5bc9ae3a398", "MaximumParquetFiles");
            RockMigrationHelper.AddOrUpdateEntityAttribute("Rock.Model.ServiceJob", Rock.SystemGuid.FieldType.INTEGER, "Class", "net.redeemertech.Security.ProcessIISAlerts", "Query Timeout Seconds", "Query Timeout Seconds", @"The amount of time in seconds to allow each alert query to run before timing out.", 2, @"30", "f1025648-a4e5-49a7-a008-9079d6aac649", "QueryTimeoutSeconds");
            AddOrUpdateIISAlertTriggeredSystemCommunication();

            RockMigrationHelper.AddOrUpdateEntityAttribute("Rock.Model.ServiceJob", Rock.SystemGuid.FieldType.SYSTEM_COMMUNICATION, "Class", "net.redeemertech.Security.ProcessIISAlerts", "Alert Email", "Alert Email", @"The system communication used to notify recipients when an IIS alert trips. The merge fields AlertType, AlertName, AlertDate, AlertTime, Summary, and AlertHistoryUrl are available.", 3, IISAlertTriggeredSystemCommunicationGuid, ProcessIISAlertsAlertEmailAttributeGuid, "AlertEmail");
            RockMigrationHelper.AddOrUpdateEntityAttribute("Rock.Model.ServiceJob", Rock.SystemGuid.FieldType.PAGE_REFERENCE, "Class", "net.redeemertech.Security.ProcessIISAlerts", "Alert History Detail Page", "Alert History Detail Page", @"The page that displays a single tripped alert history record.", 4, @"", "652fbada-170c-42b1-b846-614f31c7f6c8", "AlertHistoryDetailPage");
        }

        public override void Down()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_IISAlertHistory]', N'U') IS NOT NULL DROP TABLE [dbo].[_net_redeemertech_IISAlertHistory];
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_IISAlert]', N'U') IS NOT NULL DROP TABLE [dbo].[_net_redeemertech_IISAlert];" );

            Sql($@"
                DELETE FROM [ServiceJob]
                WHERE [Guid] IN ('{ProcessIISAlertsJobGuid}')");

            Sql($@"
                DELETE FROM [SystemCommunication]
                WHERE [Guid] IN ('{IISAlertTriggeredSystemCommunicationGuid}')");
        }

        private void AddOrUpdateServiceJob(string guid, string name, string description, string jobClass, string cronExpression)
        {
            Sql($@"
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
                END");
        }

        private void AddOrUpdateIISAlertTriggeredSystemCommunication()
        {
            Sql($@"
                DECLARE @SystemCommunicationGuid uniqueidentifier = '{IISAlertTriggeredSystemCommunicationGuid}';
                DECLARE @Title nvarchar(100) = N'IIS Alert Triggered';
                DECLARE @Subject nvarchar(1000) = N'{{{{ AlertType }}}} Triggered: {{{{ AlertName }}}}';
                DECLARE @Body nvarchar(max) = N'<p>An {{{{ AlertType }}}} was triggered.</p>
<dl>
    <dt>Alert</dt><dd>{{{{ AlertName }}}}</dd>
    <dt>Date</dt><dd>{{{{ AlertDate }}}}</dd>
    <dt>Time</dt><dd>{{{{ AlertTime }}}}</dd>
    <dt>Summary</dt><dd>{{{{ Summary }}}}</dd>
</dl>
{{% if AlertHistoryUrl != '''' %}}<p><a href=""{{{{ AlertHistoryUrl }}}}"">View Alert History</a></p>{{% endif %}}';

                IF EXISTS ( SELECT 1 FROM [SystemCommunication] WHERE [Guid] = @SystemCommunicationGuid )
                BEGIN
                    UPDATE [SystemCommunication]
                    SET [IsSystem] = 0
                        , [IsActive] = 1
                        , [Title] = @Title
                        , [Subject] = @Subject
                        , [Body] = @Body
                    WHERE [Guid] = @SystemCommunicationGuid;
                END
                ELSE
                BEGIN
                    INSERT INTO [SystemCommunication] (
                          [IsSystem]
                        , [IsActive]
                        , [Title]
                        , [Subject]
                        , [Body]
                        , [Guid]
                    ) VALUES (
                          0
                        , 1
                        , @Title
                        , @Subject
                        , @Body
                        , @SystemCommunicationGuid
                    );
                END");
        }

    }
}
