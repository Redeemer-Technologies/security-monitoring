using Rock;
using Rock.Plugin;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber( 9, "1.17.0" )]
    public class RestControllerSecurityList : Migration
    {
        public override void Up()
        {
            RockMigrationHelper.UpdateEntityType(
                "net.redeemertech.Security.Blocks.Blocks.RestControllerSecurityList",
                "REST Controller Security List",
                "net.redeemertech.Security.Blocks.Blocks.RestControllerSecurityList, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
                false,
                false,
                "c1c0850f-8334-4dca-86db-23ea70ce4ebc" );

            RockMigrationHelper.AddOrUpdateEntityBlockType(
                "REST Controller Security List",
                "Lists REST controllers and whether their controller-level permissions are secured.",
                "net.redeemertech.Security.Blocks.Blocks.RestControllerSecurityList",
                "net_redeemertech > Security",
                "5671e61e-3cf6-41ac-9dc8-529e27996735" );

            RockMigrationHelper.UpdateEntityType(
                "net.redeemertech.Security.Blocks.Blocks.RestActionSecurityList",
                "REST Action Security List",
                "net.redeemertech.Security.Blocks.Blocks.RestActionSecurityList, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
                false,
                false,
                "47c86a67-8e38-4431-a3ff-f0d4aaef0fc8" );

            RockMigrationHelper.AddOrUpdateEntityBlockType(
                "REST Action Security List",
                "Lists REST actions and whether their action-level permissions are secured.",
                "net.redeemertech.Security.Blocks.Blocks.RestActionSecurityList",
                "net_redeemertech > Security",
                "5dd2882d-e30f-428a-adad-5412d6522f44" );

            RockMigrationHelper.AddPage(
                true,
                "A741955F-F155-4C00-A80E-A4754FAF2A93",
                "D65F783D-87A9-4CC9-8110-E83466A0EADB",
                "REST Action Security",
                "",
                "89A7578D-F435-4997-BCFD-3FC7A6B25D3C",
                "fa fa-key ti ti-cloud-lock" );

            RockMigrationHelper.AddBlock(
                true,
                "89A7578D-F435-4997-BCFD-3FC7A6B25D3C".AsGuid(),
                null,
                "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(),
                "5DD2882D-E30F-428A-ADAD-5412D6522F44".AsGuid(),
                "REST Action Security List",
                "Main",
                @"",
                @"",
                0,
                "11817531-EEB4-480C-89C0-67EEA8B5BCFB" );
        }

        public override void Down()
        {
            RockMigrationHelper.DeleteBlock( "11817531-EEB4-480C-89C0-67EEA8B5BCFB" );
            RockMigrationHelper.DeletePage( "89A7578D-F435-4997-BCFD-3FC7A6B25D3C" );
        }
    }
}
