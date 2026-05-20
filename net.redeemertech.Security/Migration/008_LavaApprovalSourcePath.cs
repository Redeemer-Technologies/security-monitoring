using Rock;
using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 8, "1.17.0" )]
    public class LavaApprovalSourcePath : Migration
    {
        public override void Up()
        {

            // Add Page 
            //  Internal Name: Rock Security
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "5B6DBC42-8B03-4D15-8D92-AAFA28FD8616", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Rock Security", "", "A741955F-F155-4C00-A80E-A4754FAF2A93", "fa fa-lock");

            // Add Page 
            //  Internal Name: Lava Approvals
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "A741955F-F155-4C00-A80E-A4754FAF2A93", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Lava Approvals", "", "289185AA-945C-43B3-9E34-F96F1CEDE045", "fa fa-lock");

            // Add Block 
            //  Block Name: Lava Approval List
            //  Page Name: Lava Approvals
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "289185AA-945C-43B3-9E34-F96F1CEDE045".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "F15A9D07-140A-4180-BB75-DD640C73DB04".AsGuid(), "Lava Approval List", "Main", @"", @"", 0, "0C517748-5A56-4661-A332-7F5F0CC75104");

            // Add Block 
            //  Block Name: Page Menu
            //  Page Name: Rock Security
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "A741955F-F155-4C00-A80E-A4754FAF2A93".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "CACB9D1A-A820-4587-986A-D66A69EE9948".AsGuid(), "Page Menu", "Main", @"", @"", 0, "F77D844A-24AE-4440-855E-840FAFDBFCB7");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=Rock Security, Site=Rock RMS
            //   Attribute: Is Secondary Block
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("F77D844A-24AE-4440-855E-840FAFDBFCB7", "C80209A8-D9E0-4877-A8E3-1F7DBF64D4C2", @"False");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=Rock Security, Site=Rock RMS
            //   Attribute: Include Current Parameters
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("F77D844A-24AE-4440-855E-840FAFDBFCB7", "EEE71DDE-C6BC-489B-BAA5-1753E322F183", @"False");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=Rock Security, Site=Rock RMS
            //   Attribute: Template
            /*   Attribute Value: {% include '~~/Assets/Lava/PageListAsBlocks.lava' %} */
            RockMigrationHelper.AddBlockAttributeValue("F77D844A-24AE-4440-855E-840FAFDBFCB7", "1322186A-862A-4CF1-B349-28ECB67229BA", @"{% include '~~/Assets/Lava/PageListAsBlocks.lava' %}");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=Rock Security, Site=Rock RMS
            //   Attribute: Number of Levels
            /*   Attribute Value: 3 */
            RockMigrationHelper.AddBlockAttributeValue("F77D844A-24AE-4440-855E-840FAFDBFCB7", "6C952052-BC79-41BA-8B88-AB8EA3E99648", @"3");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=Rock Security, Site=Rock RMS
            //   Attribute: Include Current QueryString
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("F77D844A-24AE-4440-855E-840FAFDBFCB7", "E4CF237D-1D12-4C93-AFD7-78EB296C4B69", @"False");

            // Move IIS Analytics Page to Rock Security
            Sql($@"UPDATE [Page] SET ParentPageId = (SELECT TOP 1 [Id] FROM [Page] WHERE [Guid] = 'A741955F-F155-4C00-A80E-A4754FAF2A93') WHERE [Guid] = 'FA5D74A9-EC66-45E3-9149-BE75B33C09AD'");

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
