using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CI.Web.ViewModels.Identity
{
    public class TwoFactorAuthenticationViewModel
    {
        public bool HasAuthenticator { get; set; }

        public int RecoveryCodesLeft { get; set; }

      
        public bool Is2faEnabled { get; set; }

        public bool IsMachineRemembered { get; set; }

        
        public string StatusMessage { get; set; }
    }
}
