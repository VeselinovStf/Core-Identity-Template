using Microsoft.AspNetCore.Mvc;

namespace CI.Web.ViewModels.Identity
{
    public class GenerateRecoveryCodesViewModel
    {
        [TempData]
        public string[] RecoveryCodes { get; set; }

        public string StatusMessage { get; set; }
    }
}