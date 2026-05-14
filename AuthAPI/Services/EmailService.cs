using System.Net;
using System.Net.Mail;

namespace AuthAPI.Services
{
    public class EmailService
    {
        public async Task EnviarEmail(string destino, string assunto, string mensagem)
        {
            var smtp = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential(
                    "zikaluke9@gmail.com",
                    "abcd efgh ijkl mnop"
                ),
                EnableSsl = true
            };

            var mail = new MailMessage
            {
                From = new MailAddress("zikaluke9@gmail.com"),
                Subject = assunto,
                Body = mensagem,
                IsBodyHtml = true
            };

            mail.To.Add(destino);

            await smtp.SendMailAsync(mail);
        }
    }
}