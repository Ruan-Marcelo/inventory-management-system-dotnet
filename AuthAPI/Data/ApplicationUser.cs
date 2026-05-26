using Microsoft.AspNetCore.Identity;

namespace AuthAPI.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; } = string.Empty;

        public string Perfil { get; set; } = "Funcionario";

        public bool Ativo { get; set; } = true;

        public DateTime? ExpiraEm { get; set; }

        public DateTime CriadoEm { get; set; } = DateTime.Now;
    }
}
