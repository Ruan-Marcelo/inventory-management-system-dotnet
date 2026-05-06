namespace AuthAPI.Models
{
    public class Produto
    {
        public int Id { get; set; }

        public string Nome { get; set; } = string.Empty;

        public string? Descricao { get; set; }

        public decimal Preco { get; set; }

        public int Quantidade { get; set; }

        public bool Ativo { get; set; } = true;

        public int? CategoriaId { get; set; }

        public Categoria? Categoria { get; set; }

        public List<Movimentacao>? Movimentacoes { get; set; }
    }
}
