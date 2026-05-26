using System.Net;
using System.Net.Mail;

namespace AuthAPI.Services
{
    public class EmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task EnviarEmail(string? destino, string assunto, string mensagem)
        {
            if (string.IsNullOrWhiteSpace(destino))
            {
                return;
            }

            var enabled = _configuration.GetValue<bool>("Email:Enabled");
            if (!enabled)
            {
                return;
            }

            var host = _configuration["Email:SmtpHost"];
            var user = _configuration["Email:User"];
            var password = _configuration["Email:Password"];
            var from = _configuration["Email:From"] ?? user;
            var port = _configuration.GetValue("Email:Port", 587);

            if (string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(user) ||
                string.IsNullOrWhiteSpace(password) ||
                string.IsNullOrWhiteSpace(from))
            {
                return;
            }

            using var smtp = new SmtpClient(host)
            {
                Port = port,
                Credentials = new NetworkCredential(user, password),
                EnableSsl = true
            };

            using var mail = new MailMessage
            {
                From = new MailAddress(from),
                Subject = assunto,
                Body = mensagem,
                IsBodyHtml = true
            };

            mail.To.Add(destino);

            await smtp.SendMailAsync(mail);
        }
    }
}
