using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 6, "1.17.0" )]
    public class LavaApprovalAiReview : Migration
    {
        public override void Up()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                BEGIN
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewDateTime') IS NULL
                    BEGIN
                        ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [AIReviewDateTime] [datetime] NULL;
                    END

                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewProvider') IS NULL
                    BEGIN
                        ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [AIReviewProvider] [nvarchar](50) NULL;
                    END

                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewModel') IS NULL
                    BEGIN
                        ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [AIReviewModel] [nvarchar](100) NULL;
                    END

                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIHasVulnerabilityConcerns') IS NULL
                    BEGIN
                        ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [AIHasVulnerabilityConcerns] [bit] NULL;
                    END

                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIRiskAssessment') IS NULL
                    BEGIN
                        ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [AIRiskAssessment] [nvarchar](16) NULL;
                    END

                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewDetails') IS NULL
                    BEGIN
                        ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [AIReviewDetails] [nvarchar](max) NULL;
                    END

                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewRawResponse') IS NULL
                    BEGIN
                        ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] ADD [AIReviewRawResponse] [nvarchar](max) NULL;
                    END
                END" );
        }

        public override void Down()
        {
            Sql( @"
                IF OBJECT_ID(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'U') IS NOT NULL
                BEGIN
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewRawResponse') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [AIReviewRawResponse];
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewDetails') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [AIReviewDetails];
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIRiskAssessment') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [AIRiskAssessment];
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIHasVulnerabilityConcerns') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [AIHasVulnerabilityConcerns];
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewModel') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [AIReviewModel];
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewProvider') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [AIReviewProvider];
                    IF COL_LENGTH(N'[dbo].[_net_redeemertech_LavaApprovalSource]', N'AIReviewDateTime') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_LavaApprovalSource] DROP COLUMN [AIReviewDateTime];
                END" );
        }
    }
}
