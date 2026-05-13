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
    [Table( "_net_redeemertech_IISAlertHistory" )]
    [DataContract]
    [EntityTypeGuid("acd20dc2-8ac2-4b65-90b3-5fd3f99cd0dd")]
    public class IISAlertHistory : Model<IISAlertHistory>, IRockEntity, ISecured
    {
        [DataMember]
        public int IISAlertId { get; set; }

        [Required]
        [MaxLength( 100 )]
        [DataMember]
        public string AlertName { get; set; }

        [DataMember]
        public DateTime TrippedDateTime { get; set; }

        [DataMember]
        public int ResultCount { get; set; }

        [DataMember]
        public string ResultJson { get; set; }

        public virtual IISAlert IISAlert { get; set; }

        public override string ToString()
        {
            return AlertName;
        }
    }

    public partial class IISAlertHistoryConfiguration : EntityTypeConfiguration<IISAlertHistory>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IISAlertHistoryConfiguration"/> class.
        /// </summary>
        public IISAlertHistoryConfiguration()
        {
            this.HasRequired(s => s.IISAlert).WithMany(a => a.Histories).HasForeignKey(s => s.IISAlertId).WillCascadeOnDelete(true);

            // IMPORTANT!!
            this.HasEntitySetName("IISAlertHistory");
        }
    }
}
