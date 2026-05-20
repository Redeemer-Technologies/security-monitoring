using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 8, "1.17.0" )]
    public class LavaApprovalSourcePath : Migration
    {
        public override void Up()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'SourcePath') IS NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [SourcePath] [nvarchar](max) NULL;
                END" );
        }

        public override void Down()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                    AND COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'SourcePath') IS NOT NULL
                BEGIN
                    ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [SourcePath];
                END" );
        }
    }
}
