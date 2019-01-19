﻿
using CI.EmailSenderService.Abstract;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CI.EmailSenderService.Implementations
{
    //Separate this in new project or remove IEmailService From Web project
    public class EmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string message)
        {
            return Task.CompletedTask;
        }
    }
}