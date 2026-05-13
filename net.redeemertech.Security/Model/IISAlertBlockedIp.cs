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
    [Table( "_net_redeemertech_IISAlertBlockedIp" )]
    [DataContract]
    [EntityTypeGuid( "5a949368-dedc-4059-9801-63a5e01f833c" )]
    public class IISAlertBlockedIp : Model<IISAlertBlockedIp>, IRockEntity, ISecured
    {
        [Required]
        [MaxLength( 100 )]
        [DataMember]
        public string IpAddress { get; set; }

        [DataMember]
        public DateTime BlockedDateTime { get; set; }

        [DataMember]
        public DateTime ExpiresDateTime { get; set; }

        [DataMember]
        public int? IISAlertId { get; set; }

        [MaxLength( 100 )]
        [DataMember]
        public string AlertName { get; set; }

        [DataMember]
        public int? IISAlertHistoryId { get; set; }

        public virtual IISAlert IISAlert { get; set; }

        public virtual IISAlertHistory IISAlertHistory { get; set; }

        public override string ToString()
        {
            return IpAddress;
        }
    }

    public partial class IISAlertBlockedIpConfiguration : EntityTypeConfiguration<IISAlertBlockedIp>
    {
        public IISAlertBlockedIpConfiguration()
        {
            this.HasOptional( b => b.IISAlert ).WithMany().HasForeignKey( b => b.IISAlertId ).WillCascadeOnDelete( false );
            this.HasOptional( b => b.IISAlertHistory ).WithMany().HasForeignKey( b => b.IISAlertHistoryId ).WillCascadeOnDelete( false );
            this.HasEntitySetName( "IISAlertBlockedIp" );
        }
    }
}
