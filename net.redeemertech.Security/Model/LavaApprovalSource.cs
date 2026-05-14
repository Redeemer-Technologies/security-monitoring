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
    [Table( "_net_redeemertech_LavaApprovalSource" )]
    [DataContract]
    [EntityTypeGuid( "a248432e-3aeb-4a8f-95c3-d165b3d98904" )]
    public class LavaApprovalSource : Model<LavaApprovalSource>, IRockEntity, ISecured
    {
        [Required]
        [MaxLength( 128 )]
        [DataMember]
        public string TableName { get; set; }

        [Required]
        [MaxLength( 128 )]
        [DataMember]
        public string ColumnName { get; set; }

        [DataMember]
        public int RowId { get; set; }

        [DataMember]
        public long? SourceChecksum { get; set; }

        [MaxLength( 64 )]
        [DataMember]
        public string ContentHash { get; set; }

        [DataMember]
        public bool HasApprovalRequiredLava { get; set; }

        [DataMember]
        public string ContentPreview { get; set; }

        [DataMember]
        public DateTime LastScannedDateTime { get; set; }

        [DataMember]
        public DateTime LastSeenDateTime { get; set; }

        [DataMember]
        public DateTime? DetectedDateTime { get; set; }

        public override string ToString()
        {
            return string.Format( "{0}.{1}:{2}", TableName, ColumnName, RowId );
        }
    }

    public partial class LavaApprovalSourceConfiguration : EntityTypeConfiguration<LavaApprovalSource>
    {
        public LavaApprovalSourceConfiguration()
        {
            this.HasEntitySetName( "LavaApprovalSource" );
        }
    }
}
