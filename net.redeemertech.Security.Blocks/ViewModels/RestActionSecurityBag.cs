using System.Collections.Generic;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class RestActionSecurityBag
    {
        public string IdKey { get; set; }

        public string Method { get; set; }

        public string Path { get; set; }

        public string ApiId { get; set; }

        public string ControllerName { get; set; }

        public string ControllerClassName { get; set; }

        public int? RequestCountLast30Days { get; set; }

        public bool IsSecured { get; set; }

        public string SecurityStatus { get; set; }

        public bool IsSecurityDisabled { get; set; }

        public List<string> Reasons { get; set; }
    }
}
