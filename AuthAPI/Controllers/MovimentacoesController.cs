using AuthAPI.Data;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class MovimentacoesController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public MovimentacoesController(ApplicationDbContext context)
    {
        _context = context;
    }

    //  HISTÓRICO
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var movimentacoes = await _context.Movimentacoes
            .Include(x => x.Produto)
            .OrderByDescending(x => x.DataMovimentacao)
            .ToListAsync();

        return Ok(movimentacoes);
    }

    // entrada e saída
    [HttpPost]
    public async Task<IActionResult> Post([FromBody] Movimentacao mov)
    {
        var produto = await _context.Produtos.FindAsync(mov.ProdutoId);

        if (produto == null)
            return NotFound("Produto não encontrado");

        //  pega usuário logado
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        mov.UsuarioId = userId;

        //  regra de negócio
        if (mov.Tipo == "SAIDA" && produto.Quantidade < mov.Quantidade)
            return BadRequest("Estoque insuficiente");

        //  atualiza estoque
        if (mov.Tipo == "ENTRADA")
            produto.Quantidade += mov.Quantidade;
        else
            produto.Quantidade -= mov.Quantidade;

        _context.Movimentacoes.Add(mov);
        await _context.SaveChangesAsync();

        return Ok(mov);
    }
}