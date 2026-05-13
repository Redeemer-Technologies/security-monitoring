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

            // Add Page 
            //  Internal Name: Alerts
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD", "22D220B5-0D34-429A-B9E3-59D80AE423E7", "Alerts", "", "8381E992-47CB-472C-823A-51B2FBC87F7F", "");

            // Add Page 
            //  Internal Name: Alert Detail
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "8381E992-47CB-472C-823A-51B2FBC87F7F", "22D220B5-0D34-429A-B9E3-59D80AE423E7", "Alert Detail", "", "524EF496-663F-40F7-B990-F0548D27FBD9", "");

            // Add Page 
            //  Internal Name: IIS Alert Details
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "524EF496-663F-40F7-B990-F0548D27FBD9", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "IIS Alert Details", "", "D422AFE0-0E4F-4D3B-9C31-B209D11BE4F9", "");

            // Add Block 
            //  Block Name: IIS Alert List
            //  Page Name: Alerts
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "8381E992-47CB-472C-823A-51B2FBC87F7F".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "49531C16-1F93-49D9-BCAB-9E7FD889E1BF".AsGuid(), "IIS Alert List", "Main", @"", @"", 0, "E2FECEFB-EF53-4827-A224-F910A485AF52");

            // Add Block 
            //  Block Name: IIS Alert Detail
            //  Page Name: Alert Detail
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "524EF496-663F-40F7-B990-F0548D27FBD9".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "C8032B08-FC23-479D-90D3-9DDF049A6A3C".AsGuid(), "IIS Alert Detail", "Main", @"", @"", 0, "3A453580-49BD-4D16-943B-07CF98ACEEFB");

            // Add Block 
            //  Block Name: IIS Alert History List
            //  Page Name: Alert Detail
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "524EF496-663F-40F7-B990-F0548D27FBD9".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "655CA478-FDCF-4996-901C-6011B485E52B".AsGuid(), "IIS Alert History List", "Main", @"", @"", 1, "28642E24-EE66-4810-82D2-503DA4B5561C");

            // Add Block 
            //  Block Name: IIS Alert History Detail
            //  Page Name: IIS Alert Details
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "D422AFE0-0E4F-4D3B-9C31-B209D11BE4F9".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "DA59B549-4345-408C-B5F7-5680328B46E7".AsGuid(), "IIS Alert History Detail", "Main", @"", @"", 0, "20FBEDA7-3028-4924-B29A-B445CF6CAEAE");

            // update block order for pages with new blocks if the page,zone has multiple blocks

            // Update Order for Page: Alert Detail,  Zone: Main,  Block: IIS Alert Detail
            Sql(@"UPDATE [Block] SET [Order] = 0 WHERE [Guid] = '3A453580-49BD-4D16-943B-07CF98ACEEFB'");

            // Update Order for Page: Alert Detail,  Zone: Main,  Block: IIS Alert History List
            Sql(@"UPDATE [Block] SET [Order] = 1 WHERE [Guid] = '28642E24-EE66-4810-82D2-503DA4B5561C'");


            // Add Block 
            //  Block Name: HTML Content
            //  Page Name: IIS Analytics
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "19B61D65-37E3-459F-A44F-DEF0089118A3".AsGuid(), "HTML Content", "Sidebar1", @"", @"", 0, "CFBEF7C0-6948-461A-9CEF-E5DE16756EF4");

            // Add/Update HtmlContent for Block: HTML Content
            RockMigrationHelper.UpdateHtmlContentBlock("CFBEF7C0-6948-461A-9CEF-E5DE16756EF4", $@"<a class=""btn btn-default btn-block mb-4"" href=""/page/{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '1eb38156-8e6e-4d62-b7a0-6a3313b938b1'").ToStringSafe()}""><i class=""fa fa-bell""></i> Alerts</a>", "1CECC2DC-745C-4EC4-97DF-5B196A700F6B");

            // Update Order for Page: IIS Analytics,  Zone: Sidebar1,  Block: HTML Content
            Sql(@"UPDATE [Block] SET [Order] = 0 WHERE [Guid] = 'CFBEF7C0-6948-461A-9CEF-E5DE16756EF4'");

            // Update Order for Page: IIS Analytics,  Zone: Sidebar1,  Block: Page Menu
            Sql(@"UPDATE [Block] SET [Order] = 1 WHERE [Guid] = '0A281859-4CFF-4A93-B802-87AA96230AF7'");


            // Add Block Attribute Value
            //   Block: IIS Alert List
            //   BlockType: IIS Alert List
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Alerts, Site=Rock RMS
            //   Attribute: Detail Page
            /*   Attribute Value: 524ef496-663f-40f7-b990-f0548d27fbd9 */
            //   Skip If Already Exists: true
            RockMigrationHelper.AddBlockAttributeValue(true, "E2FECEFB-EF53-4827-A224-F910A485AF52", "FED8BAEC-1758-4DFA-84F2-C394C8F34616", @"524ef496-663f-40f7-b990-f0548d27fbd9");

            // Add Block Attribute Value
            //   Block: IIS Alert History List
            //   BlockType: IIS Alert History List
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Alert Detail, Site=Rock RMS
            //   Attribute: Detail Page
            /*   Attribute Value: d422afe0-0e4f-4d3b-9c31-b209d11be4f9 */
            //   Skip If Already Exists: true
            RockMigrationHelper.AddBlockAttributeValue(true, "28642E24-EE66-4810-82D2-503DA4B5561C", "2AE8485C-0589-4C6B-9BD4-0CB24E613C64", @"d422afe0-0e4f-4d3b-9c31-b209d11be4f9");
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
