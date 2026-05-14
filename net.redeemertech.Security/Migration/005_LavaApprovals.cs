using Rock;
using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 5, "1.17.0" )]
    public class LavaApprovals : Migration
    {
        public override void Up()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApproval]', N'U') IS NULL
                BEGIN
                    CREATE TABLE [dbo].[_net_redeemertech_LavaApproval] (
                        [Id] [int] IDENTITY(1,1) NOT NULL,
                        [ContentHash] [nvarchar](64) NOT NULL,
                        [ApprovedDateTime] [datetime] NOT NULL,
                        [ApprovedByPersonAliasId] [int] NULL,
                        [ApprovalNote] [nvarchar](max) NULL,
                        [ApprovedContent] [nvarchar](max) NOT NULL,
                        [CreatedDateTime] [datetime] NULL,
                        [ModifiedDateTime] [datetime] NULL,
                        [CreatedByPersonAliasId] [int] NULL,
                        [ModifiedByPersonAliasId] [int] NULL,
                        [Guid] [uniqueidentifier] NOT NULL,
                        [ForeignId] [int] NULL,
                        [ForeignGuid] [uniqueidentifier] NULL,
                        [ForeignKey] [nvarchar](100) NULL,
                        CONSTRAINT [PK__net_redeemertech_LavaApproval] PRIMARY KEY CLUSTERED ([Id] ASC)
                    );
                    CREATE UNIQUE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApproval_Guid] ON [dbo].[_net_redeemertech_LavaApproval] ([Guid] ASC);
                    CREATE UNIQUE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApproval_ContentHash] ON [dbo].[_net_redeemertech_LavaApproval] ([ContentHash] ASC);
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NULL
                BEGIN
                    CREATE TABLE [dbo].[_net_redeemertech_LavaApprovalSource] (
                        [Id] [int] IDENTITY(1,1) NOT NULL,
                        [TableName] [nvarchar](128) NOT NULL,
                        [ColumnName] [nvarchar](128) NOT NULL,
                        [RowId] [int] NOT NULL,
                        [SourceChecksum] [bigint] NULL,
                        [ContentHash] [nvarchar](64) NULL,
                        [HasApprovalRequiredLava] [bit] NOT NULL CONSTRAINT [DF__net_redeemertech_LavaApprovalSource_HasApprovalRequiredLava] DEFAULT ((0)),
                        [ContentPreview] [nvarchar](max) NULL,
                        [LastScannedDateTime] [datetime] NOT NULL,
                        [DetectedDateTime] [datetime] NULL,
                        [CreatedDateTime] [datetime] NULL,
                        [ModifiedDateTime] [datetime] NULL,
                        [CreatedByPersonAliasId] [int] NULL,
                        [ModifiedByPersonAliasId] [int] NULL,
                        [Guid] [uniqueidentifier] NOT NULL,
                        [ForeignId] [int] NULL,
                        [ForeignGuid] [uniqueidentifier] NULL,
                        [ForeignKey] [nvarchar](100) NULL,
                        CONSTRAINT [PK__net_redeemertech_LavaApprovalSource] PRIMARY KEY CLUSTERED ([Id] ASC)
                    );
                    CREATE UNIQUE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApprovalSource_Guid] ON [dbo].[_net_redeemertech_LavaApprovalSource] ([Guid] ASC);
                    CREATE UNIQUE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApprovalSource_Source] ON [dbo].[_net_redeemertech_LavaApprovalSource] ([TableName] ASC, [ColumnName] ASC, [RowId] ASC);
                    CREATE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApprovalSource_SourceChecksum] ON [dbo].[_net_redeemertech_LavaApprovalSource] ([TableName] ASC, [ColumnName] ASC, [SourceChecksum] ASC);
                    CREATE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApprovalSource_ContentHash] ON [dbo].[_net_redeemertech_LavaApprovalSource] ([ContentHash] ASC);
                    CREATE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApprovalSource_ApprovalRequired] ON [dbo].[_net_redeemertech_LavaApprovalSource] ([HasApprovalRequiredLava] ASC, [ContentHash] ASC);
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND EXISTS (
                        SELECT 1
                        FROM sys.columns c
                        INNER JOIN sys.types ty ON ty.user_type_id = c.user_type_id
                        WHERE c.object_id = OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]')
                            AND c.[name] = N'SourceChecksum'
                            AND ty.[name] <> N'bigint'
                    )
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM sys.indexes
                        WHERE [name] = N'IX__net_redeemertech_LavaApprovalSource_SourceChecksum'
                            AND object_id = OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]')
                    )
                    BEGIN
                        DROP INDEX [IX__net_redeemertech_LavaApprovalSource_SourceChecksum]
                        ON [dbo].[_net_redeemertech_LavaApprovalSource];
                    END

                    UPDATE [dbo].[_net_redeemertech_LavaApprovalSource]
                    SET [SourceChecksum] = NULL;

                    ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource]
                    ALTER COLUMN [SourceChecksum] [bigint] NULL;
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApproval]', N'U') IS NOT NULL
                    AND COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApproval]', N'ApprovedContent') IS NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_LavaApproval]
                    ADD [ApprovedContent] [nvarchar](max) NOT NULL CONSTRAINT [DF__net_redeemertech_LavaApproval_ApprovedContent] DEFAULT (N'');

                    ALTER TABLE [dbo].[_net_redeemertech_LavaApproval]
                    DROP CONSTRAINT [DF__net_redeemertech_LavaApproval_ApprovedContent];
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1
                        FROM sys.indexes
                        WHERE [name] = N'IX__net_redeemertech_LavaApprovalSource_SourceChecksum'
                            AND object_id = OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]')
                    )
                BEGIN
                    CREATE NONCLUSTERED INDEX [IX__net_redeemertech_LavaApprovalSource_SourceChecksum]
                    ON [dbo].[_net_redeemertech_LavaApprovalSource] ([TableName] ASC, [ColumnName] ASC, [SourceChecksum] ASC);
                END" );

            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Model.LavaApproval", "Lava Approval", "net.redeemertech.Security.Model.LavaApproval, net.redeemertech.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "726b4827-8bd5-4311-90c5-d1c8b1a5a73f" );
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Model.LavaApprovalSource", "Lava Approval Source", "net.redeemertech.Security.Model.LavaApprovalSource, net.redeemertech.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "a248432e-3aeb-4a8f-95c3-d165b3d98904" );
            RockMigrationHelper.UpdateEntityType( "net.redeemertech.Security.Blocks.Blocks.LavaApprovalList", "Lava Approval List", "net.redeemertech.Security.Blocks.Blocks.LavaApprovalList, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "81c3194f-db46-4a7e-aaff-4dfdcc66d5f4" );
            RockMigrationHelper.AddOrUpdateEntityBlockType( "Lava Approval List", "Lists Lava scripts that require administrator approval.", "net.redeemertech.Security.Blocks.Blocks.LavaApprovalList", "net_redeemertech > Security", "f15a9d07-140a-4180-bb75-dd640c73db04" );

            RockMigrationHelper.AddPage( true, "8381E992-47CB-472C-823A-51B2FBC87F7F", "22D220B5-0D34-429A-B9E3-59D80AE423E7", "Lava Approvals", "", "67ee74e2-b4a5-458a-836b-e43597f81800", "" );
            RockMigrationHelper.AddBlock( true, "67ee74e2-b4a5-458a-836b-e43597f81800".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "f15a9d07-140a-4180-bb75-dd640c73db04".AsGuid(), "Lava Approval List", "Main", @"", @"", 0, "0c36c3c1-b645-4a3b-95c8-e6ed090827d8" );
        }

        public override void Down()
        {
            RockMigrationHelper.DeleteBlock( "0c36c3c1-b645-4a3b-95c8-e6ed090827d8" );
            RockMigrationHelper.DeletePage( "67ee74e2-b4a5-458a-836b-e43597f81800" );
            RockMigrationHelper.DeleteBlockType( "f15a9d07-140a-4180-bb75-dd640c73db04" );

            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL DROP TABLE [dbo].[_net_redeemertech_LavaApprovalSource];
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApproval]', N'U') IS NOT NULL DROP TABLE [dbo].[_net_redeemertech_LavaApproval];" );
        }
    }
}
