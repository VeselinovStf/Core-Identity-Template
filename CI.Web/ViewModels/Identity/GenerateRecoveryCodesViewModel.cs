using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CI.Web.ViewModels.Identity
{
    public class GenerateRecoveryCodesViewModel
    {

        [TempData]
        public string[] RecoveryCodes { get; set; }

        public string StatusMessage { get; set; }
    }
}
