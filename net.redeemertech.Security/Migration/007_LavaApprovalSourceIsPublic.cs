using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 7, "1.17.0" )]
    public class LavaApprovalSourceIsPublic : Migration
    {
        public override void Up()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'IsPublic') IS NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [IsPublic] [bit] NULL;
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'ReferencedShortcodes') IS NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [ReferencedShortcodes] [nvarchar](max) NULL;
                END" );
        }

        public override void Down()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'IsPublic') IS NOT NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [IsPublic];
                END

                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'ReferencedShortcodes') IS NOT NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [ReferencedShortcodes];
                END" );
        }
    }
}
