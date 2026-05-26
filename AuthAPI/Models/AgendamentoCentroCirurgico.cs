namespace AuthAPI.Models
{
    public class AgendamentoCentroCirurgico
    {
        public int Id { get; set; }

        public string Paciente { get; set; } = string.Empty;

        public string Procedimento { get; set; } = string.Empty;

        public string VeterinarioResponsavel { get; set; } = string.Empty;

        public DateTime Inicio { get; set; }

        public DateTime Fim { get; set; }

        public string Status { get; set; } = "Agendado";

        public string? Observacao { get; set; }

        public string? UsuarioId { get; set; }

        public DateTime CriadoEm { get; set; } = DateTime.Now;
    }
}
