namespace AuthAPI.Models
{
    public class Categoria
    {
        public int Id { get; set; }

        public string Nome { get; set; }

        public bool Ativo { get; set; } = true;

        public List<Produto>? Produtos { get; set; }
    }
}
