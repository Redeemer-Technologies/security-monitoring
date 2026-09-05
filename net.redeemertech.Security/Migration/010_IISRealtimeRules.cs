using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 10, "1.17.0" )]
    public class IISRealtimeRules : Migration
    {
        public override void Up()
        {
            Sql( @"
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'EvaluationMode') IS NULL
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [EvaluationMode] [int] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_EvaluationMode] DEFAULT ((0));

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'RequestStage') IS NULL
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [RequestStage] [int] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_RequestStage] DEFAULT ((0));

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'ConditionLogic') IS NULL
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [ConditionLogic] [int] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_ConditionLogic] DEFAULT ((0));

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'ConditionsJson') IS NULL
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [ConditionsJson] [nvarchar](max) NULL;

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockRequest') IS NULL
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [BlockRequest] [bit] NOT NULL CONSTRAINT [DF__net_redeemertech_IISAlert_BlockRequest] DEFAULT ((0));

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockResponseStatusCode') IS NULL
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [BlockResponseStatusCode] [int] NULL;

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockResponseMessage') IS NULL
                    ALTER TABLE [dbo].[_net_redeemertech_IISAlert] ADD [BlockResponseMessage] [nvarchar](max) NULL;" );
        }

        public override void Down()
        {
            Sql( @"
                DECLARE @sql nvarchar(max);

                SELECT @sql = N'ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP CONSTRAINT [' + dc.name + N']'
                FROM sys.default_constraints dc
                INNER JOIN sys.columns c ON c.default_object_id = dc.object_id
                INNER JOIN sys.tables t ON t.object_id = c.object_id
                WHERE t.name = '_net_redeemertech_IISAlert' AND c.name = 'BlockRequest';
                IF @sql IS NOT NULL EXEC sp_executesql @sql;

                SET @sql = NULL;
                SELECT @sql = N'ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP CONSTRAINT [' + dc.name + N']'
                FROM sys.default_constraints dc
                INNER JOIN sys.columns c ON c.default_object_id = dc.object_id
                INNER JOIN sys.tables t ON t.object_id = c.object_id
                WHERE t.name = '_net_redeemertech_IISAlert' AND c.name = 'ConditionLogic';
                IF @sql IS NOT NULL EXEC sp_executesql @sql;

                SET @sql = NULL;
                SELECT @sql = N'ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP CONSTRAINT [' + dc.name + N']'
                FROM sys.default_constraints dc
                INNER JOIN sys.columns c ON c.default_object_id = dc.object_id
                INNER JOIN sys.tables t ON t.object_id = c.object_id
                WHERE t.name = '_net_redeemertech_IISAlert' AND c.name = 'RequestStage';
                IF @sql IS NOT NULL EXEC sp_executesql @sql;

                SET @sql = NULL;
                SELECT @sql = N'ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP CONSTRAINT [' + dc.name + N']'
                FROM sys.default_constraints dc
                INNER JOIN sys.columns c ON c.default_object_id = dc.object_id
                INNER JOIN sys.tables t ON t.object_id = c.object_id
                WHERE t.name = '_net_redeemertech_IISAlert' AND c.name = 'EvaluationMode';
                IF @sql IS NOT NULL EXEC sp_executesql @sql;

                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockResponseMessage') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [BlockResponseMessage];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockResponseStatusCode') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [BlockResponseStatusCode];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'BlockRequest') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [BlockRequest];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'ConditionsJson') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [ConditionsJson];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'ConditionLogic') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [ConditionLogic];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'RequestStage') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [RequestStage];
                IF COL_LENGTH(N'[dbo].[_net_redeemertech_IISAlert]', N'EvaluationMode') IS NOT NULL ALTER TABLE [dbo].[_net_redeemertech_IISAlert] DROP COLUMN [EvaluationMode];" );
        }
    }
}
