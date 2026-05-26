using System.Text.Json.Serialization;
namespace AuthAPI.Models
{
    public class Produto
    {
        public int Id { get; set; }

        public string Nome { get; set; } = string.Empty;

        public string? Descricao { get; set; }

        public decimal Preco { get; set; }

        public int Quantidade { get; set; }

        public int EstoqueMinimo { get; set; } = 5;

        public string UnidadeMedida { get; set; } = "un";

        public string? CodigoInterno { get; set; }

        public bool Ativo { get; set; } = true;

        public string? UsuarioId { get; set; }

        public int? CategoriaId { get; set; }

        public Categoria? Categoria { get; set; }

        [JsonIgnore]
        public List<Movimentacao>? Movimentacoes { get; set; }

        // SMTP
        public bool EmailEstoqueBaixoEnviado { get; set; } = false;

        public bool EmailProdutoZeradoEnviado { get; set; } = false;
    }
}
