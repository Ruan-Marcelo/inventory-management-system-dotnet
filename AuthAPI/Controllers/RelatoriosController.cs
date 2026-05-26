using AuthAPI.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;

namespace AuthAPI.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class RelatoriosController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public RelatoriosController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet("dashboard")]
        public async Task<IActionResult> Dashboard()
        {
            var produtos = await _context.Produtos
                .Include(p => p.Categoria)
                .Where(p => p.Ativo)
                .ToListAsync();

            var movimentacoes = await _context.Movimentacoes.ToListAsync();
            var hoje = DateTime.Today;

            var proximasCirurgias = await _context.AgendamentosCentroCirurgico
                .Where(a => a.Status == "Agendado" && a.Inicio >= hoje)
                .OrderBy(a => a.Inicio)
                .Take(5)
                .ToListAsync();

            return Ok(new
            {
                totalProdutos = produtos.Count,
                estoqueBaixo = produtos.Count(p => p.Quantidade > 0 && p.Quantidade <= p.EstoqueMinimo),
                produtosEsgotados = produtos.Count(p => p.Quantidade <= 0),
                totalMovimentacoes = movimentacoes.Count,
                valorTotalEstoque = produtos.Sum(p => p.Preco * p.Quantidade),
                entradas = movimentacoes.Count(m => m.Tipo == "ENTRADA"),
                saidas = movimentacoes.Count(m => m.Tipo == "SAIDA"),
                produtosPorCategoria = produtos
                    .GroupBy(p => p.Categoria != null ? p.Categoria.Nome : "Sem categoria")
                    .Select(g => new { categoria = g.Key, total = g.Count() }),
                alertas = produtos
                    .Where(p => p.Quantidade <= p.EstoqueMinimo)
                    .OrderBy(p => p.Quantidade)
                    .Select(p => new
                    {
                        p.Id,
                        p.Nome,
                        p.Quantidade,
                        p.EstoqueMinimo,
                        p.UnidadeMedida,
                        categoria = p.Categoria != null ? p.Categoria.Nome : "Sem categoria"
                    }),
                proximasCirurgias
            });
        }

        [HttpGet("movimentacoes")]
        public async Task<IActionResult> Movimentacoes([FromQuery] DateTime? inicio, [FromQuery] DateTime? fim, [FromQuery] string? tipo)
        {
            var query = _context.Movimentacoes
                .Include(m => m.Produto)
                .ThenInclude(p => p!.Categoria)
                .AsQueryable();

            if (inicio.HasValue)
            {
                query = query.Where(m => m.DataMovimentacao >= inicio.Value);
            }

            if (fim.HasValue)
            {
                query = query.Where(m => m.DataMovimentacao <= fim.Value);
            }

            if (!string.IsNullOrWhiteSpace(tipo))
            {
                query = query.Where(m => m.Tipo == tipo);
            }

            var dados = await query
                .OrderByDescending(m => m.DataMovimentacao)
                .Select(m => new
                {
                    produto = m.Produto != null ? m.Produto.Nome : "Produto removido",
                    categoria = m.Produto != null && m.Produto.Categoria != null ? m.Produto.Categoria.Nome : "Sem categoria",
                    m.Tipo,
                    m.Quantidade,
                    m.DataMovimentacao,
                    m.Observacao
                })
                .ToListAsync();

            return Ok(dados);
        }

        [HttpGet("estoque")]
        public async Task<IActionResult> Estoque()
        {
            var dados = await _context.Produtos
                .Include(p => p.Categoria)
                .Where(p => p.Ativo)
                .OrderBy(p => p.Nome)
                .Select(p => new
                {
                    p.Nome,
                    categoria = p.Categoria != null ? p.Categoria.Nome : "Sem categoria",
                    p.Quantidade,
                    p.EstoqueMinimo,
                    p.UnidadeMedida,
                    p.Preco,
                    valorTotal = p.Preco * p.Quantidade,
                    status = p.Quantidade <= 0 ? "Esgotado" : p.Quantidade <= p.EstoqueMinimo ? "Baixo" : "OK"
                })
                .ToListAsync();

            return Ok(dados);
        }

        [HttpGet("estoque.csv")]
        public async Task<IActionResult> EstoqueCsv()
        {
            var dados = await _context.Produtos
                .Include(p => p.Categoria)
                .Where(p => p.Ativo)
                .OrderBy(p => p.Nome)
                .ToListAsync();

            var csv = new StringBuilder();
            csv.AppendLine("Produto;Categoria;Quantidade;Estoque minimo;Unidade;Preco;Valor total;Status");

            foreach (var p in dados)
            {
                var status = p.Quantidade <= 0 ? "Esgotado" : p.Quantidade <= p.EstoqueMinimo ? "Baixo" : "OK";
                csv.AppendLine($"{Sanitizar(p.Nome)};{Sanitizar(p.Categoria?.Nome ?? "Sem categoria")};{p.Quantidade};{p.EstoqueMinimo};{Sanitizar(p.UnidadeMedida)};{p.Preco:0.00};{p.Preco * p.Quantidade:0.00};{status}");
            }

            return File(Encoding.UTF8.GetBytes(csv.ToString()), "text/csv", "relatorio-estoque.csv");
        }

        private static string Sanitizar(string valor)
        {
            return valor.Replace(";", ",").Replace(Environment.NewLine, " ");
        }
    }
}
