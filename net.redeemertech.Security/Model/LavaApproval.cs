using Rock.Data;
using Rock.Security;
using Rock.SystemGuid;

using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.ModelConfiguration;
using System.Runtime.Serialization;

namespace net.redeemertech.Security.Model
{
    [Table( "_net_redeemertech_LavaApproval" )]
    [DataContract]
    [EntityTypeGuid( "726b4827-8bd5-4311-90c5-d1c8b1a5a73f" )]
    public class LavaApproval : Model<LavaApproval>, IRockEntity, ISecured
    {
        [Required]
        [MaxLength( 64 )]
        [DataMember]
        public string ContentHash { get; set; }

        [DataMember]
        public DateTime ApprovedDateTime { get; set; }

        [DataMember]
        public int? ApprovedByPersonAliasId { get; set; }

        [DataMember]
        public string ApprovalNote { get; set; }

        [Required]
        [DataMember]
        public string ApprovedContent { get; set; }

        public override string ToString()
        {
            return ContentHash;
        }
    }

    public partial class LavaApprovalConfiguration : EntityTypeConfiguration<LavaApproval>
    {
        public LavaApprovalConfiguration()
        {
            this.HasEntitySetName( "LavaApproval" );
        }
    }
}
