using Rock;
using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 4, "1.17.0" )]
    public class IISAlertBlocking : Migration
    {
        public override void Up()
        {
            Sql( @"
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockIpAddress') IS NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [BlockIpAddress] [bit] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_BlockIpAddress] DEFAULT ((0));
                END

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockIpAddressMinutes') IS NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [BlockIpAddressMinutes] [int] NULL;
                END

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'LockOutUserAccounts') IS NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [LockOutUserAccounts] [bit] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_LockOutUserAccounts] DEFAULT ((0));
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_IISAlertBlockedIp]', N'U') IS NULL
                BEGIN
                    CREATE TABLE [dbo].[_net_redeemertech_IISAlertBlockedIp] (
                        [Id] [int] IDENTITY(1,1) NOT NULL,
                        [IpAddress] [nvarchar](100) NOT NULL,
                        [BlockedDateTime] [datetime] NOT NULL,
                        [ExpiresDateTime] [datetime] NOT NULL,
                        [IISAlertId] [int] NULL,
                        [AlertName] [nvarchar](100) NULL,
                        [IISAlertHistoryId] [int] NULL,
                        [CreatedDateTime] [datetime] NULL,
                        [ModifiedDateTime] [datetime] NULL,
                        [CreatedByPersonAliasId] [int] NULL,
                        [ModifiedByPersonAliasId] [int] NULL,
                        [Guid] [uniqueidentifier] NOT NULL,
                        [ForeignId] [int] NULL,
                        [ForeignGuid] [uniqueidentifier] NULL,
                        [ForeignKey] [nvarchar](100) NULL,
                        CONSTRAINT [PK__net_redeemertech_IISAlertBlockedIp] PRIMARY KEY CLUSTERED ([Id] ASC),
                        CONSTRAINT [FK__net_redeemertech_IISAlertBlockedIp_IISAlert] FOREIGN KEY ([IISAlertId]) REFERENCES [dbo].[_net_redeemertech_IISAlert] ([Id]),
                        CONSTRAINT [FK__net_redeemertech_IISAlertBlockedIp_IISAlertHistory] FOREIGN KEY ([IISAlertHistoryId]) REFERENCES [dbo].[_net_redeemertech_IISAlertHistory] ([Id])
                    );
                    CREATE UNIQUE NONCLUSTERED INDEX [IX__net_redeemertech_IISAlertBlockedIp_Guid] ON [dbo].[_net_redeemertech_IISAlertBlockedIp] ([Guid] ASC);
                    CREATE NONCLUSTERED INDEX [IX__net_redeemertech_IISAlertBlockedIp_IpAddress_ExpiresDateTime] ON [dbo].[_net_redeemertech_IISAlertBlockedIp] ([IpAddress] ASC, [ExpiresDateTime] ASC);
                END" );

            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Model.IISAlertBlockedIp", "IIS Alert Blocked IP", "net.redeemertech.Security.Model.IISAlertBlockedIp, net.redeemertech.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "5a949368-dedc-4059-9801-63a5e01f833c" );
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.IISAlertBlockHttpModule", "IIS Alert Block HTTP Module", "net.redeemertech.Security.IISAlertBlockHttpModule, net.redeemertech.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "25fc7aa8-e1de-4f4f-9b53-9f25c5ce7c1b" );
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Blocks.Blocks.IISBlockedIpList", "IIS Blocked IP List", "net.redeemertech.Security.Blocks.Blocks.IISBlockedIpList, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "a2991b20-e33e-4b20-8a1c-bd37caf96cb5" );
            RockMigrationHelper.AddOrUpdateEntityBlockType( "IIS Blocked IP List", "Lists IP addresses blocked by IIS alerts.", "net.redeemertech.Security.Blocks.Blocks.IISBlockedIpList", "net_redeemertech > Security", "8deec723-675f-4999-9847-67a819bd01ab" );
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute( "8deec723-675f-4999-9847-67a819bd01ab", Rock.SystemGuid.FieldType.PAGE_REFERENCE, "History Detail Page", "HistoryDetailPage", "History Detail Page", @"Page containing the IIS Alert History Detail block.", 0, @"", "d398ad0c-0e72-41d2-a663-53f79baa2a16");

            RockMigrationHelper.AddPage( true, "8381E992-47CB-472C-823A-51B2FBC87F7F", "22D220B5-0D34-429A-B9E3-59D80AE423E7", "Blocked IPs", "", "4458e0cc-c2a5-40a4-82ad-2ae254e01b6a", "" );
            RockMigrationHelper.AddBlock( true, "4458e0cc-c2a5-40a4-82ad-2ae254e01b6a".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "8deec723-675f-4999-9847-67a819bd01ab".AsGuid(), "IIS Blocked IP List", "Main", @"", @"", 0, "c4009176-5728-452c-8253-4797846f600f");
            RockMigrationHelper.AddBlockAttributeValue( true, "c4009176-5728-452c-8253-4797846f600f", "d398ad0c-0e72-41d2-a663-53f79baa2a16", @"d422afe0-0e4f-4d3b-9c31-b209d11be4f9" );

            // Add/Update HtmlContent for Block: HTML Content
            RockMigrationHelper.UpdateHtmlContentBlock("CFBEF7C0-6948-461A-9CEF-E5DE16756EF4", $@"<a class=""btn btn-default btn-block mb-4"" href=""/page/{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '8381E992-47CB-472C-823A-51B2FBC87F7F'").ToStringSafe()}""><i class=""fa fa-bell""></i> Alerts</a>
            <a class=""btn btn-default btn-block mb-4"" href=""/page/{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '4458e0cc-c2a5-40a4-82ad-2ae254e01b6a'").ToStringSafe()}""><i class=""fa fa-ban""></i> Blocked IPs</a>", "1CECC2DC-745C-4EC4-97DF-5B196A700F6B");
        }

        public override void Down()
        {
            RockMigrationHelper.DeleteBlock("c4009176-5728-452c-8253-4797846f600f");
            RockMigrationHelper.DeletePage("4458e0cc-c2a5-40a4-82ad-2ae254e01b6a");
            RockMigrationHelper.DeleteBlockType( "8deec723-675f-4999-9847-67a819bd01ab" );

            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_IISAlertBlockedIp]', N'U') IS NOT NULL DROP TABLE [dbo].[_net_redeemertech_IISAlertBlockedIp];

                DECLARE @sql nvarchar(max);
                SELECT @sql = N'ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP CONSTRAINT [' + dc.name + N']'
                FROM sys.default_constraints dc
                INNER JOIN sys.columns c ON c.default_object_id = dc.object_id
                INNER JOIN sys.tables t ON t.object_id = c.object_id
                WHERE t.name = '_net_redeemertech_IISAlert' AND c.name = 'LockOutUserAccounts';
                IF @sql IS NOT NULL EXEC sp_executesql @sql;

                SET @sql = NULL;
                SELECT @sql = N'ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP CONSTRAINT [' + dc.name + N']'
                FROM sys.default_constraints dc
                INNER JOIN sys.columns c ON c.default_object_id = dc.object_id
                INNER JOIN sys.tables t ON t.object_id = c.object_id
                WHERE t.name = '_net_redeemertech_IISAlert' AND c.name = 'BlockIpAddress';
                IF @sql IS NOT NULL EXEC sp_executesql @sql;

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'LockOutUserAccounts') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [LockOutUserAccounts];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockIpAddressMinutes') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [BlockIpAddressMinutes];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockIpAddress') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [BlockIpAddress];" );
        }
    }
}
