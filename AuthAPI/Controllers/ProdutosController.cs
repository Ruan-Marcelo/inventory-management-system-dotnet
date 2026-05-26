using AuthAPI.Data;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ProdutosController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public ProdutosController(ApplicationDbContext context)
    {
        _context = context;
    }

    // list
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var produtos = await _context.Produtos
            .Include(x => x.Categoria)
            .Where(x => x.Ativo)
            .OrderBy(x => x.Nome)
            .ToListAsync();

        return Ok(produtos);
    }


    // create
    [HttpPost]
    public async Task<IActionResult> Post([FromBody] Produto produto)
    {
        var erro = ValidarProduto(produto);
        if (erro != null)
        {
            return BadRequest(erro);
        }

        _context.Produtos.Add(produto);
        await _context.SaveChangesAsync();

        return Ok(produto);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Put(int id, Produto produto)
    {
        if (id != produto.Id)
            return BadRequest();

        var produtoDb = await _context.Produtos.FindAsync(id);

        if (produtoDb == null)
            return NotFound();

        var erro = ValidarProduto(produto);
        if (erro != null)
        {
            return BadRequest(erro);
        }

        produtoDb.Nome = produto.Nome;
        produtoDb.Descricao = produto.Descricao;
        produtoDb.Preco = produto.Preco;
        produtoDb.Quantidade = produto.Quantidade;
        produtoDb.EstoqueMinimo = produto.EstoqueMinimo;
        produtoDb.UnidadeMedida = produto.UnidadeMedida;
        produtoDb.CodigoInterno = produto.CodigoInterno;
        produtoDb.CategoriaId = produto.CategoriaId;

        await _context.SaveChangesAsync();

        return Ok(produtoDb);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var produto = await _context.Produtos.FindAsync(id);

        if (produto == null)
            return NotFound();

        produto.Ativo = false;

        _context.Produtos.Update(produto);

        await _context.SaveChangesAsync();

        return Ok(new
        {
            mensagem = "Produto desativado"
        });
    }

    [HttpGet("inativos")]
    public async Task<IActionResult> GetInativos()
    {
        var produtos = await _context.Produtos
            .Include(p => p.Categoria)
            .Where(p => !p.Ativo)
            .ToListAsync();

        return Ok(produtos);
    }

    [HttpPut("reativar/{id}")]
    public async Task<IActionResult> Reativar(int id)
    {
        var produto = await _context.Produtos.FindAsync(id);

        if (produto == null)
            return NotFound();

        produto.Ativo = true;

        await _context.SaveChangesAsync();

        return Ok(produto);
    }

    private static string? ValidarProduto(Produto produto)
    {
        if (string.IsNullOrWhiteSpace(produto.Nome))
            return "Nome do produto é obrigatório";

        if (produto.Preco < 0)
            return "Preço não pode ser negativo";

        if (produto.Quantidade < 0)
            return "Quantidade não pode ser negativa";

        if (produto.EstoqueMinimo < 0)
            return "Estoque mínimo não pode ser negativo";

        if (string.IsNullOrWhiteSpace(produto.UnidadeMedida))
            produto.UnidadeMedida = "un";

        produto.Nome = produto.Nome.Trim();
        produto.UnidadeMedida = produto.UnidadeMedida.Trim();
        produto.CodigoInterno = produto.CodigoInterno?.Trim();

        return null;
    }
}
