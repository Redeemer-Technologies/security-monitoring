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
        }

        public override void Down()
        {
        }
    }
}
