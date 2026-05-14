using AuthAPI.Data;
using AuthAPI.Models;
using AuthAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class MovimentacoesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly EmailService _emailService;
    private readonly UserManager<ApplicationUser> _userManager;

    // APENAS UM CONSTRUTOR
    public MovimentacoesController(
        ApplicationDbContext context,
        EmailService emailService,
        UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _emailService = emailService;
        _userManager = userManager;
    }

    // HISTÓRICO
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var movimentacoes = await _context.Movimentacoes
            .Include(x => x.Produto)
            .OrderByDescending(x => x.DataMovimentacao)
            .ToListAsync();

        return Ok(movimentacoes);
    }

    // ENTRADA E SAÍDA
    [HttpPost]
    public async Task<IActionResult> Post([FromBody] Movimentacao mov)
    {
        var produto = await _context.Produtos.FindAsync(mov.ProdutoId);

        if (produto == null)
            return NotFound("Produto não encontrado");

        // pega usuário logado
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        mov.UsuarioId = userId;

        // regra de negócio
        if (mov.Tipo == "SAIDA" && produto.Quantidade < mov.Quantidade)
            return BadRequest("Estoque insuficiente");

        // atualiza estoque
        if (mov.Tipo == "ENTRADA")
            produto.Quantidade += mov.Quantidade;
        else
            produto.Quantidade -= mov.Quantidade;

        // =========================
        // ENVIO DE EMAILS
        // =========================

        var usuarios = _userManager.Users.ToList();

        foreach (var usuario in usuarios)
        {
            // ESTOQUE BAIXO
            if (produto.Quantidade <= 5 &&
                produto.Quantidade > 0 &&
                !produto.EmailEstoqueBaixoEnviado)
            {
                await _emailService.EnviarEmail(
                    usuario.Email,
                    "⚠ Estoque Baixo",
                    $@"
                    <h2>Produto com estoque baixo</h2>

                    <p>
                        O produto <b>{produto.Nome}</b>
                        está com apenas
                        <b>{produto.Quantidade}</b>
                        unidades.
                    </p>
                    "
                );

                produto.EmailEstoqueBaixoEnviado = true;
            }

            // PRODUTO ESGOTADO
            if (produto.Quantidade <= 0 &&
                !produto.EmailProdutoZeradoEnviado)
            {
                await _emailService.EnviarEmail(
                    usuario.Email,
                    "❌ Produto Esgotado",
                    $@"
                    <h2>Produto esgotado</h2>

                    <p>
                        O produto <b>{produto.Nome}</b>
                        está sem estoque.
                    </p>
                    "
                );

                produto.EmailProdutoZeradoEnviado = true;
            }
        }

        // RESETA ALERTAS
        if (produto.Quantidade > 5)
        {
            produto.EmailEstoqueBaixoEnviado = false;
            produto.EmailProdutoZeradoEnviado = false;
        }

        _context.Movimentacoes.Add(mov);

        await _context.SaveChangesAsync();

        return Ok(mov);
    }
}