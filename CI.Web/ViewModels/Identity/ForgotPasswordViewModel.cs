using System.ComponentModel.DataAnnotations;

namespace CI.Web.ViewModels.Identity
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}