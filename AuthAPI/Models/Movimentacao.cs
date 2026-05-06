namespace AuthAPI.Models
{
    public class Movimentacao
    {
        public int Id { get; set; }

        public int ProdutoId { get; set; }

        public Produto? Produto { get; set; }

        public string Tipo { get; set; } // entrada e saida boy

        public int Quantidade { get; set; }

        public DateTime DataMovimentacao { get; set; } = DateTime.Now;

        public string? UsuarioId { get; set; }

        public string? Observacao { get; set; }
    }
}
