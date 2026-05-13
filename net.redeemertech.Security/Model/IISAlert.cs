using Rock.Data;
using Rock.Security;
using Rock.SystemGuid;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.ModelConfiguration;
using System.Runtime.Serialization;

namespace net.redeemertech.Security.Model
{
    [Table( "_net_redeemertech_IISAlert" )]
    [DataContract]
    [EntityTypeGuid("590c8327-928e-4edb-8427-3d816d5b50ec")]
    public class IISAlert : Model<IISAlert>, IRockEntity, ISecured
    {
        [Required]
        [MaxLength( 100 )]
        [DataMember]
        public string Name { get; set; }

        [DataMember]
        public string Description { get; set; }

        [DataMember]
        public bool IsActive { get; set; }

        [Required]
        [DataMember]
        public string Query { get; set; }

        [MaxLength( 100 )]
        [DataMember]
        public string DateRange { get; set; }

        [DataMember]
        public string NotificationEmails { get; set; }

        [DataMember]
        public int EvaluationFrequencyMinutes { get; set; }

        [DataMember]
        public DateTime? LastRunDateTime { get; set; }

        public virtual List<IISAlertHistory> Histories { get; set; }

        public override string ToString()
        {
            return Name;
        }
    }

    public partial class IISAlertConfiguration : EntityTypeConfiguration<IISAlert>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IISAlertConfiguration"/> class.
        /// </summary>
        public IISAlertConfiguration()
        {
            this.HasMany(a => a.Histories).WithRequired(s => s.IISAlert).HasForeignKey(s => s.IISAlertId).WillCascadeOnDelete(true);

            // IMPORTANT!!
            this.HasEntitySetName("IISAlert");
        }
    }

}
