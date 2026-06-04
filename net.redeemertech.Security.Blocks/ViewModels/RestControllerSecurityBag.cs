using System.Collections.Generic;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class RestControllerSecurityBag
    {
        public string IdKey { get; set; }

        public string Name { get; set; }

        public string ClassName { get; set; }

        public bool IsSecured { get; set; }

        public string SecurityStatus { get; set; }

        public bool IsSecurityDisabled { get; set; }

        public List<string> Reasons { get; set; }
    }
}
