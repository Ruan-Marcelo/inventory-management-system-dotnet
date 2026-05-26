namespace AuthAPI.Models
{
    public class UsuarioUpdateModel
    {
        public string Name { get; set; } = string.Empty;
        public string Perfil { get; set; } = "Funcionario";
        public bool Ativo { get; set; } = true;
        public DateTime? ExpiraEm { get; set; }
    }
}
