using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

using Rock;
using Rock.Plugin;
using Rock.Security;
using Rock.Model;

namespace net.redeemertech.Security.Migrations
{
    [MigrationNumber(1, "1.17.0")]
    class Pages : Migration
    {
        public override void Up()
        {
            // Add Log Query Block Type
            RockMigrationHelper.UpdateEntityType("net.redeemertech.Security.Blocks.Blocks.LogQuery", "IIS Log Query", "net.redeemertech.Security.Blocks.Blocks.LogQuery, net.redeemertech.Security.Blocks, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", false, false, "ea5f4786-e909-4f1d-b12e-f6e8284987c1");
            RockMigrationHelper.AddOrUpdateEntityBlockType("IIS Log Query", "Queries IIS log parquet files created by the Process IIS Logs job using DuckDB.", "net.redeemertech.Security.Blocks.Blocks.LogQuery", "net_redeemertech > Security", "46a5cc4c-673a-46e3-b100-98104dcc0539");

            // Add Page 
            //  Internal Name: IIS Analytics
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "5B6DBC42-8B03-4D15-8D92-AAFA28FD8616", "22D220B5-0D34-429A-B9E3-59D80AE423E7", "IIS Analytics", "", "FA5D74A9-EC66-45E3-9149-BE75B33C09AD", "fa fa-glasses");

            // Add Page 
            //  Internal Name: Top URLs
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Top URLs", "", "5C23DE72-8A3E-433F-AE4E-C4B7392B1179", "");

            // Add Page 
            //  Internal Name: Daily Active Users By Domain
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Daily Active Users By Domain", "", "7327A7BB-FE73-421E-8C55-6AB5425830E7", "");

            // Add Page 
            //  Internal Name: Error Pages/404s
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Error Pages/404s", "", "7B6B8BC1-D697-4DBE-A1BE-D6D87F305DAE", "");

            // Add Page 
            //  Internal Name: Traffic by User
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Traffic by User", "", "A70BB399-057B-46A4-ABBF-7855BEDCA726", "");

            // Add Page 
            //  Internal Name: Specific User
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "A70BB399-057B-46A4-ABBF-7855BEDCA726", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Specific User", "", "02526A81-81BB-4BFC-A375-B184E521501E", "");

            // Add Page 
            //  Internal Name: Specific Page
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "7B6B8BC1-D697-4DBE-A1BE-D6D87F305DAE", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Specific Page", "", "766F0CC4-42DF-41B9-A1D7-4EA5DC5E97BF", "");

            // Add Page 
            //  Internal Name: Specific Page
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "5C23DE72-8A3E-433F-AE4E-C4B7392B1179", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "Specific Page", "", "388ABED2-C9CA-4A59-9843-FC84A55D8295", "");


            // Add Page 
            //  Internal Name: IIS Log Query
            //  Site: Rock RMS
            RockMigrationHelper.AddPage(true, "7F1F4130-CB98-473B-9DE1-7A886D2283ED", "D65F783D-87A9-4CC9-8110-E83466A0EADB", "IIS Log Query", "", "B2CFE96E-42FD-45BD-8F93-41F01E82574A", "fa fa-glasses");


            // Add Block 
            //  Block Name: Log Query
            //  Page Name: IIS Log Query
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "B2CFE96E-42FD-45BD-8F93-41F01E82574A".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "C9244478-AA69-458A-8CE9-471B229705EE");

            // Add Block 
            //  Block Name: Page Menu
            //  Page Name: IIS Analytics
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "CACB9D1A-A820-4587-986A-D66A69EE9948".AsGuid(), "Page Menu", "Sidebar1", @"", @"", 0, "0A281859-4CFF-4A93-B802-87AA96230AF7");

            // Add Block 
            //  Block Name: All Requests
            //  Page Name: IIS Analytics
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "All Requests", "Main", @"<div class=""row"">", @"</div>", 0, "411FACDE-72BF-4670-835C-1350291BAE38");

            // Add Block 
            //  Block Name: Data Egress
            //  Page Name: IIS Analytics
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Data Egress", "Main", @"", @"</div>", 2, "DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403");

            // Add Block 
            //  Block Name: Users
            //  Page Name: IIS Analytics
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Users", "Main", @"<div class=""row"">", @"", 1, "A7BBF719-610C-4FF0-AEC8-68D740BDCAA3");

            // Add Block 
            //  Block Name: Top users
            //  Page Name: IIS Analytics
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Top users", "Main", @"<div class=""row"">", @"", 3, "679B1693-3A8C-4209-BE43-EFD0B30E3948");

            // Add Block 
            //  Block Name: Top URLs
            //  Page Name: IIS Analytics
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "FA5D74A9-EC66-45E3-9149-BE75B33C09AD".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Top URLs", "Main", @"", @"</div>", 4, "061D2970-370E-4FF0-A8DF-392FA7B2126F");

            // Add Block 
            //  Block Name: Log Query
            //  Page Name: Top URLs
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "5C23DE72-8A3E-433F-AE4E-C4B7392B1179".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "265D8CBE-4AE6-456F-924A-6F571037F324");

            // Add Block 
            //  Block Name: Log Query
            //  Page Name: Daily Active Users By Domain
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "7327A7BB-FE73-421E-8C55-6AB5425830E7".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1");

            // Add Block 
            //  Block Name: Log Query
            //  Page Name: Error Pages/404s
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "7B6B8BC1-D697-4DBE-A1BE-D6D87F305DAE".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "2034E874-D57F-4352-BFDA-DEE1EE8CB660");

            // Add Block 
            //  Block Name: Log Query
            //  Page Name: Traffic by User
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "A70BB399-057B-46A4-ABBF-7855BEDCA726".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA");

            // Add Block 
            //  Block Name: Log Query
            //  Page Name: Specific User
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "02526A81-81BB-4BFC-A375-B184E521501E".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "9F630E83-6590-4F4F-A5BB-629EDCA84639");

            // Add Block 
            //  Block Name: Log Query
            //  Page Name: Specific Page
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "766F0CC4-42DF-41B9-A1D7-4EA5DC5E97BF".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "177D8EB6-54E1-427E-BDAF-C01C15DB011E");

            // Add Block 
            //  Block Name: Log Query
            //  Page Name: Specific Page
            //  Layout: -
            //  Site: Rock RMS
            RockMigrationHelper.AddBlock(true, "388ABED2-C9CA-4A59-9843-FC84A55D8295".AsGuid(), null, "C2D29296-6A87-47A9-A753-EE4E9159C4C4".AsGuid(), "46a5cc4c-673a-46e3-b100-98104dcc0539".AsGuid(), "Log Query", "Main", @"", @"", 0, "00F2C59C-B218-45E7-8A4E-C1AC49D67127");

            // update block order for pages with new blocks if the page,zone has multiple blocks

            // Update Order for Page: IIS Analytics,  Zone: Main,  Block: All Requests
            Sql(@"UPDATE [Block] SET [Order] = 0 WHERE [Guid] = '411FACDE-72BF-4670-835C-1350291BAE38'");

            // Update Order for Page: IIS Analytics,  Zone: Main,  Block: Data Egress
            Sql(@"UPDATE [Block] SET [Order] = 2 WHERE [Guid] = 'DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403'");

            // Update Order for Page: IIS Analytics,  Zone: Main,  Block: Top URLs
            Sql(@"UPDATE [Block] SET [Order] = 4 WHERE [Guid] = '061D2970-370E-4FF0-A8DF-392FA7B2126F'");

            // Update Order for Page: IIS Analytics,  Zone: Main,  Block: Top users
            Sql(@"UPDATE [Block] SET [Order] = 3 WHERE [Guid] = '679B1693-3A8C-4209-BE43-EFD0B30E3948'");

            // Update Order for Page: IIS Analytics,  Zone: Main,  Block: Users
            Sql(@"UPDATE [Block] SET [Order] = 1 WHERE [Guid] = 'A7BBF719-610C-4FF0-AEC8-68D740BDCAA3'");

            // Update Order for Page: IIS Analytics,  Zone: Sidebar1,  Block: Page Menu
            Sql(@"UPDATE [Block] SET [Order] = 0 WHERE [Guid] = '0A281859-4CFF-4A93-B802-87AA96230AF7'");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Parquet Folder
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "9C204CD0-1233-41C5-818A-C5DA439445AA", "Parquet Folder", "ParquetFolder", "Parquet Folder", @"The folder containing parquet files created by Process IIS Logs. Relative paths are resolved under App_Data.", 0, @"IisLogParquet", "77990981-11EF-4E5B-9639-B98A6772EDCB");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Maximum Parquet Files
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "A75DFC58-7A1B-4799-BF31-451B2BBE38FF", "Maximum Parquet Files", "MaximumParquetFiles", "Maximum Parquet Files", @"The maximum number of parquet files to include in a query. Use this as a safeguard if the log folder grows unexpectedly.", 1, @"1000", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Enabled Lava Commands
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "4BD9088F-5CC6-89B1-45FC-A2AAFFC7CC0D", "Enabled Lava Commands", "EnabledLavaCommands", "Enabled Lava Commands", @"The Lava commands that should be enabled when resolving the SQL query and Lava output template.", 2, @"", "DC68F9CE-2535-496F-BF49-548C0FE3C326");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: SQL Query
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "9C204CD0-1233-41C5-818A-C5DA439445AA", "SQL Query", "Query", "SQL Query", @"The DuckDB SQL query to execute. Use [[logs]] in the FROM clause as the placeholder for the IIS log parquet source.", 0, @"SELECT *
FROM [[logs]]
ORDER BY date DESC, time DESC
LIMIT 100", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Timeout Length
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "A75DFC58-7A1B-4799-BF31-451B2BBE38FF", "Timeout Length", "Timeout", "Timeout Length", @"The amount of time in seconds to allow the query to run before timing out.", 0, @"30", "42BA98E2-2174-41B5-BD8A-458EC6C9F852");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Results Display Mode
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "7525C4CB-EE6B-41D4-9B64-A08048D5A5C0", "Results Display Mode", "ResultsDisplayMode", "Results Display Mode", @"Determines how the results should be displayed.", 0, @"grid", "F293A285-4DD9-4524-9090-DF3E6FF0EC46");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Grid Title
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "9C204CD0-1233-41C5-818A-C5DA439445AA", "Grid Title", "GridTitle", "Grid Title", @"The title of the grid's panel.", 0, @"", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Lava Template
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "9C204CD0-1233-41C5-818A-C5DA439445AA", "Lava Template", "LavaTemplate", "Lava Template", @"Formatting to apply to the returned results. The template has access to rows and tables.", 0, @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow.AvailableKeys %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}", "EC4F40E3-1837-4985-A67D-E7C81515DEF6");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Show Query on Page
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "1EDAFDED-DFE6-4334-B019-6EECBA89E05A", "Show Query on Page", "ShowQueryOnPage", "Show Query on Page", @"Shows an editable SQL editor and Run button on the page. The most recently run query is saved to the user's block preferences.", 0, @"False", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Date Range
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "55810BC5-45EA-4044-B783-0CCE0A445C6F", "Date Range", "DateRange", "Date Range", @"Only parquet files whose filename date stamp falls within this range will be included in the query.", 0, @"Last|7|Day||", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Selection URL
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "9C204CD0-1233-41C5-818A-C5DA439445AA", "Selection URL", "SelectionUrl", "Selection URL", @"The URL to redirect individuals to when they click on a row in the grid. Any column's value can be used in the URL by including it in braces. For example: ~/Person/{Id}", 0, @"", "5CF8EE6C-A8CB-487C-9CDC-031B496F071F");

            // Attribute for BlockType
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Attribute: Query Parameters
            RockMigrationHelper.AddOrUpdateBlockTypeAttribute("46a5cc4c-673a-46e3-b100-98104dcc0539", "9C204CD0-1233-41C5-818A-C5DA439445AA", "Query Parameters", "QueryParams", "Query Parameters", @"Specify the parameters required by the query using the format 'param1=value;param2=value'. Parameters matching URL page parameter values will automatically use those values. Use DuckDB named parameters in SQL like $param1.", 0, @"", "234AD1B4-E4BA-4542-9422-AD3DACAEA890");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT *
FROM [[logs]]
ORDER BY date DESC, time DESC
LIMIT 100");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Grid Title
            /*   Attribute Value: Logs */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB", @"Logs");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow.AvailableKeys %}
    {{ colums | ToJSON }}<br>
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Log Query, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("C9244478-AA69-458A-8CE9-471B229705EE", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow | AllKeysFromDictionary %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Grid Title
            /*   Attribute Value: Daily Active Users by site */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB", @"Daily Active Users by site");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    date, 
    ""cs-host"" AS virtual_site, 
    COUNT(DISTINCT ""cs-username"") AS daily_active_users ,
    COUNT(DISTINCT ""c-ip"") as daily_active_ips
FROM [[logs]] 
WHERE ""cs-username"" != '-' 
GROUP BY date, ""cs-host"" 
ORDER BY date DESC, daily_active_users DESC, ""cs-host"";");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Daily Active Users By Domain, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("E25D414D-AEA5-4E9A-B3E1-F1CCBC3601E1", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    ""cs-host"" AS virtual_site, 
    ""cs-uri-stem"" AS cs_uri_stem, 
    SUM(""sc-bytes"") / 1048576.0 AS total_mb_downloaded,
    COUNT(DISTINCT ""cs-username"") AS users,
    COUNT(*) as requests
FROM [[logs]]
GROUP BY ""cs-host"", ""cs-uri-stem""
ORDER BY total_mb_downloaded DESC 
LIMIT 100;");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Grid Title
            /*   Attribute Value: Top URLs */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB", @"Top URLs");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow | AllKeysFromDictionary %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Top URLs, Site=Rock RMS
            //   Attribute: Selection URL
            /*   Attribute Value: /page/867?page={cs_uri_stem} */
            RockMigrationHelper.AddBlockAttributeValue("265D8CBE-4AE6-456F-924A-6F571037F324", "5CF8EE6C-A8CB-487C-9CDC-031B496F071F", $@"/page/{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '388ABED2-C9CA-4A59-9843-FC84A55D8295'")}?page={{cs_uri_stem}}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Selection URL
            /*   Attribute Value: /page/866?page={endpoint} */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "5CF8EE6C-A8CB-487C-9CDC-031B496F071F", $@"/page/{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '766F0CC4-42DF-41B9-A1D7-4EA5DC5E97BF'")}?page={{endpoint}}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Grid Title
            /*   Attribute Value: Error Pages */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB", @"Error Pages");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow | AllKeysFromDictionary %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    ""cs-host"" AS virtual_site, 
    ""cs-uri-stem"" AS endpoint, 
    ""sc-status"" AS error_code, 
    COUNT(*) AS error_count 
FROM [[logs]]
WHERE ""sc-status"" >= 400 AND ""sc-status"" < 600 
GROUP BY ""cs-host"", ""cs-uri-stem"", ""sc-status"" 
ORDER BY error_count DESC;");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Error Pages/404s, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("2034E874-D57F-4352-BFDA-DEE1EE8CB660", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    ""cs-host"" AS virtual_site, 
    ""cs-username"" AS user, 
    COUNT(DISTINCT ""c-ip"") AS ips,
    SUM(""sc-bytes"") / 1048576.0 AS total_mb_downloaded,
    COUNT(DISTINCT ""cs-uri-stem"") AS pages,
    COUNT(*) AS requests
FROM [[logs]]
WHERE ""cs-username"" != '-'
GROUP BY ""cs-host"", ""cs-username""
ORDER BY requests DESC");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Grid Title
            /*   Attribute Value: Traffic by user */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB", @"Traffic by user");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow | AllKeysFromDictionary %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Traffic by User, Site=Rock RMS
            //   Attribute: Selection URL
            /*   Attribute Value: /page/865?user={user} */
            RockMigrationHelper.AddBlockAttributeValue("08C5EDFB-D809-4B3F-9EF0-BABFEB1637DA", "5CF8EE6C-A8CB-487C-9CDC-031B496F071F", $@"/page/{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '02526A81-81BB-4BFC-A375-B184E521501E'")}?user={{user}}");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"False");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    <div class=""card"">
        <div class=""card-body"">
            <h3 class=""card-title"">All Requests (Last 7 Days)</h3>
            <canvas id=""dailyRequestsChart"" style=""width: 100%; max-height: 400px;""></canvas>
        </div>
    </div>
    
    <script>
        (function() {
            // 1. Define the function that actually builds the chart
            function renderChart() {
                var canvas = document.getElementById('dailyRequestsChart');
                if (!canvas) return;
                
                var ctx = canvas.getContext('2d');
                
                var chartLabels = [
                    {% for row in rows %}
                        ""{{ row['log_date'] | Escape }}""{% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];
                
                var totalRequestsData = [
                    {% for row in rows %}
                        {{ row['total_requests'] }}{% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];

                var errorRequestsData = [
                    {% for row in rows %}
                        {{ row['error_requests'] }}{% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];

                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: chartLabels,
                        datasets: [
                            {
                                label: 'Total Requests',
                                data: totalRequestsData,
                                borderColor: 'rgba(75, 192, 192, 1)',
                                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                                fill: true,
                                tension: 0.3,
                                pointBackgroundColor: 'rgba(75, 192, 192, 1)',
                                yAxisID: 'y' // Maps to the left axis
                            },
                            {
                                label: 'Error Responses',
                                data: errorRequestsData,
                                borderColor: 'rgba(255, 99, 132, 1)',
                                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                                fill: true,
                                tension: 0.3,
                                pointBackgroundColor: 'rgba(255, 99, 132, 1)',
                                yAxisID: 'y1' // Maps to the right axis
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: {
                            mode: 'index',
                            intersect: false,
                        },
                        scales: {
                            x: {
                                title: {
                                    display: true,
                                    text: 'Date'
                                }
                            },
                            y: {
                                type: 'linear',
                                display: true,
                                position: 'left',
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Total Requests'
                                }
                            },
                            y1: {
                                type: 'linear',
                                display: true,
                                position: 'right',
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Error Responses (4xx/5xx)'
                                },
                                // Prevent the grid lines for the second axis from drawing over the first axis's grid lines
                                grid: {
                                    drawOnChartArea: false,
                                }
                            }
                        }
                    }
                });
            }

            // 2. Check if Chart.js is already loaded
            if (typeof Chart !== 'undefined') {
                renderChart();
            } else {
                var script = document.createElement('script');
                script.src = '/Scripts/Chartjs/Chart.min.js';
                script.onload = function() {
                    renderChart();
                };
                document.head.appendChild(script);
            }
        })();
    </script>
{% else %}
    <div class=""alert alert-info"">No requests found for the past 30 days.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: lavaTemplate */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"lavaTemplate");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    CAST(""date"" AS DATE) AS log_date, 
    COUNT(*) AS total_requests,
    SUM(CASE WHEN CAST(""sc-status"" AS INTEGER) >= 400 THEN 1 ELSE 0 END) AS error_requests
FROM [[logs]] 
WHERE CAST(""date"" AS DATE) >= CURRENT_DATE - INTERVAL 30 DAY
GROUP BY CAST(""date"" AS DATE) 
ORDER BY log_date ASC;");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: All Requests
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("411FACDE-72BF-4670-835C-1350291BAE38", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    CAST(""date"" AS DATE) AS log_date, 
    SUM(CAST(""sc-bytes"" AS BIGINT)) AS total_bytes_sent
FROM [[logs]] 
WHERE CAST(""date"" AS DATE) >= CURRENT_DATE - INTERVAL 30 DAY
GROUP BY CAST(""date"" AS DATE) 
ORDER BY log_date ASC;");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: lavaTemplate */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"lavaTemplate");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    <div class=""card mt-4 mb-4"">
        <div class=""card-body"">
            <h3 class=""card-title"">Data Egress (Last 7 Days)</h3>
            <canvas id=""dataEgressChart"" style=""width: 100%; max-height: 400px;""></canvas>
        </div>
    </div>
    
    <script>
        (function() {
            function renderChart() {
                var canvas = document.getElementById('dataEgressChart');
                if (!canvas) return;
                
                var ctx = canvas.getContext('2d');
                
                var chartLabels = [
                    {% for row in rows %}
                        ""{{ row['log_date'] | Escape }}""{% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];
                
                var chartData = [
                    {% for row in rows %}
                        // Convert raw bytes to Megabytes (MB)
                        ({{ row['total_bytes_sent'] | default: 0 }} / 1048576).toFixed(2){% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];

                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: chartLabels,
                        datasets: [{
                            label: 'Data Egress (MB)',
                            data: chartData,
                            borderColor: 'rgba(153, 102, 255, 1)',
                            backgroundColor: 'rgba(153, 102, 255, 0.2)',
                            fill: true,
                            tension: 0.3,
                            pointBackgroundColor: 'rgba(153, 102, 255, 1)'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Megabytes (MB)'
                                }
                            },
                            x: {
                                title: {
                                    display: true,
                                    text: 'Date'
                                }
                            }
                        }
                    }
                });
            }

            if (typeof Chart !== 'undefined') {
                renderChart();
            } else {
                var script = document.createElement('script');
                script.src = '/Scripts/Chartjs/Chart.min.js';
                script.onload = function() {
                    renderChart();
                };
                document.head.appendChild(script);
            }
        })();
    </script>
{% else %}
    <div class=""alert alert-info"">No data egress records found for the past 30 days.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"False");

            // Add Block Attribute Value
            //   Block: Data Egress
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("DB4EDD2D-D3B9-4349-9F3A-69ADD8FCC403", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    <div class=""card mt-4 mb-4"">
        <div class=""card-body"">
            <h3 class=""card-title"">Users (Last 7 Days)</h3>
            <canvas id=""distinctUsersChart"" style=""width: 100%; max-height: 400px;""></canvas>
        </div>
    </div>
    
    <script>
        (function() {
            function renderChart() {
                var canvas = document.getElementById('distinctUsersChart');
                if (!canvas) return;
                
                var ctx = canvas.getContext('2d');
                
                var chartLabels = [
                    {% for row in rows %}
                        ""{{ row['log_date'] | Escape }}""{% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];
                
                var uniqueIpsData = [
                    {% for row in rows %}
                        {{ row['unique_ips'] | default: 0 }}{% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];

                var uniqueUsernamesData = [
                    {% for row in rows %}
                        {{ row['unique_usernames'] | default: 0 }}{% if forloop.last == false %},{% endif %}
                    {% endfor %}
                ];

                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: chartLabels,
                        datasets: [
                            {
                                label: 'Distinct IPs',
                                data: uniqueIpsData,
                                borderColor: 'rgba(255, 159, 64, 1)',
                                backgroundColor: 'rgba(255, 159, 64, 0.2)',
                                fill: true,
                                tension: 0.3,
                                pointBackgroundColor: 'rgba(255, 159, 64, 1)',
                                yAxisID: 'y'
                            },
                            {
                                label: 'Distinct Usernames',
                                data: uniqueUsernamesData,
                                borderColor: 'rgba(54, 162, 235, 1)',
                                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                                fill: true,
                                tension: 0.3,
                                pointBackgroundColor: 'rgba(54, 162, 235, 1)',
                                yAxisID: 'y1'
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: {
                            mode: 'index',
                            intersect: false,
                        },
                        scales: {
                            x: {
                                title: {
                                    display: true,
                                    text: 'Date'
                                }
                            },
                            y: {
                                type: 'linear',
                                display: true,
                                position: 'left',
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Unique Client IPs'
                                }
                            },
                            y1: {
                                type: 'linear',
                                display: true,
                                position: 'right',
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Unique Logged-in Users'
                                },
                                // Prevent background grid lines from overlapping the left axis
                                grid: {
                                    drawOnChartArea: false,
                                }
                            }
                        }
                    }
                });
            }

            if (typeof Chart !== 'undefined') {
                renderChart();
            } else {
                var script = document.createElement('script');
                script.src = '/Scripts/Chartjs/Chart.min.js';
                script.onload = function() {
                    renderChart();
                };
                document.head.appendChild(script);
            }
        })();
    </script>
{% else %}
    <div class=""alert alert-info"">No distinct user records found for the past 30 days.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"False");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: lavaTemplate */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"lavaTemplate");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    CAST(""date"" AS DATE) AS log_date, 
    COUNT(DISTINCT ""c-ip"") AS unique_ips,
    COUNT(DISTINCT CASE WHEN ""cs-username"" != '-' AND ""cs-username"" IS NOT NULL THEN ""cs-username"" ELSE NULL END) AS unique_usernames
FROM [[logs]] 
WHERE CAST(""date"" AS DATE) >= CURRENT_DATE - INTERVAL 30 DAY
GROUP BY CAST(""date"" AS DATE) 
ORDER BY log_date ASC;");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("A7BBF719-610C-4FF0-AEC8-68D740BDCAA3", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Number of Levels
            /*   Attribute Value: 3 */
            RockMigrationHelper.AddBlockAttributeValue("0A281859-4CFF-4A93-B802-87AA96230AF7", "6C952052-BC79-41BA-8B88-AB8EA3E99648", @"3");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Include Current QueryString
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("0A281859-4CFF-4A93-B802-87AA96230AF7", "E4CF237D-1D12-4C93-AFD7-78EB296C4B69", @"False");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Include Current Parameters
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("0A281859-4CFF-4A93-B802-87AA96230AF7", "EEE71DDE-C6BC-489B-BAA5-1753E322F183", @"False");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("0A281859-4CFF-4A93-B802-87AA96230AF7", "1322186A-862A-4CF1-B349-28ECB67229BA", @"{% if Page.DisplayChildPages and Page.Pages != empty %}
<div class=""panel panel-default"">
    <div class=""panel-heading"">
        <h3 class=""panel-title"">All Reports</h3>
    </div>
    <div class=""panel-body"">
        <!-- Textbox for filtering the links -->
        <input type=""text"" id=""linkFilter"" class=""form-control"" placeholder=""Filter pages..."">
    </div>
    
    <!-- ul structured as a Bootstrap list-group -->
    <ul class=""list-group"" id=""filterableLinkList"">
        {% for childPage in Page.Pages %}
            <li class=""list-group-item {% if childPage.Current %}active{% endif %}"">
                <a href=""{{ childPage.Url }}"">{{ childPage.Title }}</a>
            </li>
        {% endfor %}
        
        {% for includedPage in IncludePageList %}
            {% assign path = 'Global' | Page:'Path' %}
            {% assign attributeParts = includedPage | PropertyToKeyValue %}
            <li class=""list-group-item {% if path == attributeParts.Value %}active{% endif %}"">
                <a href=""{{ attributeParts.Value }}"">{{ attributeParts.Key }}</a>
            </li>
        {% endfor %}
    </ul>
</div>

<!-- JavaScript to filter the list items -->
<script>
    document.addEventListener(""DOMContentLoaded"", function() {
        var filterInput = document.getElementById('linkFilter');
        var listItems = document.querySelectorAll('#filterableLinkList .list-group-item');

        filterInput.addEventListener('keyup', function() {
            var filterValue = this.value.toLowerCase();

            for (var i = 0; i < listItems.length; i++) {
                // Get the text from the <a> tag inside the <li>
                var linkText = listItems[i].textContent || listItems[i].innerText;
                
                // Show or hide the <li> based on whether it matches the filter
                if (linkText.toLowerCase().indexOf(filterValue) > -1) {
                    listItems[i].style.display = '';
                } else {
                    listItems[i].style.display = 'none';
                }
            }
        });
    });
</script>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Page Menu
            //   BlockType: Page Menu
            //   Category: CMS
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Is Secondary Block
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("0A281859-4CFF-4A93-B802-87AA96230AF7", "C80209A8-D9E0-4877-A8E3-1F7DBF64D4C2", @"False");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT
    ""cs-username"" AS user, 
    COUNT(*) AS requests,
    COUNT(DISTINCT ""cs-uri-stem"") AS URLs,
    COUNT(DISTINCT ""c-ip"") AS IPs,
    ROUND(SUM(""sc-bytes"") / 1048576.0,0) AS ""MB Down""
FROM [[logs]]
WHERE ""cs-username"" != '-'
GROUP BY ""cs-host"", ""cs-username""
ORDER BY requests DESC
LIMIT 5");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: lavaTemplate */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"lavaTemplate");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"False");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", $@"<div class=""card mt-4 mb-4"">
    <div class=""card-body"">
        <h3 class=""card-title"">Top Users</h3>
        
        {{% assign firstRow = rows | First %}}
        {{% if firstRow %}}
            {{% assign columns = firstRow.AvailableKeys %}}
            <div class=""table-responsive"">
                <table class=""table table-condensed table-striped"" style=""white-space: nowrap;"">
                    <thead>
                        <tr>
                            {{% for column in columns %}}
                                <th>{{ column }}</th>
                            {{% endfor %}}
                        </tr>
                    </thead>
                    <tbody>
                        {{% for row in rows %}}
                            <tr>
                                {{% for column in columns %}}
                                    {{% if column == ""user"" %}}
                                    <td><a href=""/page/{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '02526A81-81BB-4BFC-A375-B184E521501E'")}?user={{ row[column] | Escape }}"">{{ row[column] | Escape }}</a></td>
                                    {{% else %}}
                                    <td>{{ row[column] | Escape }}</td>
                                    {{% endif %}}
                                {{% endfor %}}
                            </tr>
                        {{% endfor %}}
                    </tbody>
                </table>
            </div>
        {{% else %}}
            <div class=""alert alert-info"">No results found.</div>
        {{% endif %}}
    </div>
</div>");

            // Add Block Attribute Value
            //   Block: Top users
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("679B1693-3A8C-4209-BE43-EFD0B30E3948", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", $@"<div class=""card mt-4 mb-4"">
    <div class=""card-body"">
        <h3 class=""card-title"">Top URLs</h3>
        
        {{% assign firstRow = rows | First %}}
        {{% if firstRow %}}
            {{% assign columns = firstRow.AvailableKeys %}}
            <div class=""table-responsive"">
                <table class=""table table-condensed table-striped"" style=""white-space: nowrap;"">
                    <thead>
                        <tr>
                            {{% for column in columns %}}
                                <th>{{ column }}</th>
                            {{% endfor %}}
                        </tr>
                    </thead>
                    <tbody>
                        {{% for row in rows %}}
                            <tr>
                                {{% for column in columns %}}
                                    {{% if column == ""cs_uri_stem"" %}}
                                    <td><a href=""{SqlScalar("SELECT [Id] FROM [Page] WHERE [Guid] = '388ABED2-C9CA-4A59-9843-FC84A55D8295'")}?page={{ row[column] | Escape }}"">{{ row[column] | Escape }}</a></td>
                                    {{% else %}}
                                    <td>{{ row[column] | Escape }}</td>
                                    {{% endif %}}
                                {{% endfor %}}
                            </tr>
                        {{% endfor %}}
                    </tbody>
                </table>
            </div>
        {{% else %}}
            <div class=""alert alert-info"">No results found.</div>
        {{% endif %}}
    </div>
</div>");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: False */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"False");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: lavaTemplate */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"lavaTemplate");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    ""cs-host"" AS virtual_site, 
    ""cs-uri-stem"" AS cs_uri_stem, 
    ROUND(SUM(""sc-bytes"") / 1048576.0, 0) AS ""MB Down"",
    COUNT(DISTINCT ""cs-username"") AS users,
    COUNT(DISTINCT ""c-ip"") AS IPs,
    COUNT(*) as requests
FROM [[logs]]
GROUP BY ""cs-host"", ""cs-uri-stem""
ORDER BY requests DESC 
LIMIT 5;");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Top URLs
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=IIS Analytics, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("061D2970-370E-4FF0-A8DF-392FA7B2126F", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    *
FROM [[logs]]
WHERE ""cs-username"" = $user
ORDER BY date DESC");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow.AvailableKeys %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Query Parameters
            /*   Attribute Value: user=user */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "234AD1B4-E4BA-4542-9422-AD3DACAEA890", @"user=user");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific User, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("9F630E83-6590-4F4F-A5BB-629EDCA84639", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Query Parameters
            /*   Attribute Value: page=page */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "234AD1B4-E4BA-4542-9422-AD3DACAEA890", @"page=page");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow.AvailableKeys %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Grid Title
            /*   Attribute Value: Error Page Requests */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB", @"Error Page Requests");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    *
FROM [[logs]]
WHERE ""cs-uri-stem"" = $page
ORDER BY date DESC
LIMIT 1000;");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("177D8EB6-54E1-427E-BDAF-C01C15DB011E", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Parquet Folder
            /*   Attribute Value: IisLogParquet */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "77990981-11EF-4E5B-9639-B98A6772EDCB", @"IisLogParquet");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Maximum Parquet Files
            /*   Attribute Value: 1000 */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "9C289ACE-F56E-49F6-BEAB-7C4CE2323AD9", @"1000");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: SQL Query
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "554C77F0-D14D-45C2-AE7D-7A1D62AF5ADB", @"SELECT 
    *
FROM [[logs]]
WHERE ""cs-uri-stem"" = $page
ORDER BY date DESC
LIMIT 1000;");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Timeout Length
            /*   Attribute Value: 30 */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "42BA98E2-2174-41B5-BD8A-458EC6C9F852", @"30");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Grid Title
            /*   Attribute Value: Page Requests */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "D3979B7E-C1EB-47C8-8A9B-30F414168CDB", @"Page Requests");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Results Display Mode
            /*   Attribute Value: grid */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "F293A285-4DD9-4524-9090-DF3E6FF0EC46", @"grid");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Lava Template
            /*   Attribute Value: ... */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "EC4F40E3-1837-4985-A67D-E7C81515DEF6", @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow.AvailableKeys %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Show Query on Page
            /*   Attribute Value: True */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "641EEE50-16B1-46B8-989C-2AD6BA9BAB93", @"True");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Query Parameters
            /*   Attribute Value: page=page */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "234AD1B4-E4BA-4542-9422-AD3DACAEA890", @"page=page");

            // Add Block Attribute Value
            //   Block: Log Query
            //   BlockType: Log Query
            //   Category: net_redeemertech > Security
            //   Block Location: Page=Specific Page, Site=Rock RMS
            //   Attribute: Date Range
            /*   Attribute Value: Last|7|Day|| */
            RockMigrationHelper.AddBlockAttributeValue("00F2C59C-B218-45E7-8A4E-C1AC49D67127", "BE474AC7-8C76-456B-B44C-24E61B8E4B9A", @"Last|7|Day||");
        }

        public override void Down()
        {

        }
    }
}
