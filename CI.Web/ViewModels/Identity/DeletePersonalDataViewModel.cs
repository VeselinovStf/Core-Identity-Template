﻿using System.ComponentModel.DataAnnotations;

namespace CI.Web.ViewModels.Identity
{
    public class DeletePersonalDataViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public bool RequirePassword { get; set; }
    }
}