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
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var isVeterinario = User.IsInRole("VeterinarioParceiro");

        var movimentacoes = await _context.Movimentacoes
            .Include(x => x.Produto)
            .ThenInclude(p => p!.Categoria)
            .Where(m => m.Produto != null)
            .Where(m => isVeterinario
                ? m.Produto!.UsuarioId == userId
                : m.Produto!.UsuarioId == null)
            .OrderByDescending(x => x.DataMovimentacao)
            .ToListAsync();

        return Ok(movimentacoes);
    }

    // ENTRADA E SAÍDA
    [HttpPost]
    public async Task<IActionResult> Post([FromBody] Movimentacao mov)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var isVeterinario = User.IsInRole("VeterinarioParceiro");

        var produto = await _context.Produtos
            .Where(p => isVeterinario
                ? p.UsuarioId == userId
                : p.UsuarioId == null)
            .FirstOrDefaultAsync(p => p.Id == mov.ProdutoId);

        if (produto == null || !produto.Ativo)
            return NotFound("Produto não encontrado");

        if (mov.Quantidade <= 0)
            return BadRequest("Quantidade deve ser maior que zero");

        if (mov.Tipo != "ENTRADA" && mov.Tipo != "SAIDA")
            return BadRequest("Tipo de movimentação inválido");

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

        var usuarios = isVeterinario
            ? await _userManager.Users.Where(u => u.Id == userId).ToListAsync()
            : await _userManager.Users.Where(u => u.Perfil == "Admin" || u.Perfil == "Funcionario").ToListAsync();

        foreach (var usuario in usuarios)
        {
            // ESTOQUE BAIXO
            if (produto.Quantidade <= produto.EstoqueMinimo &&
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
                        {produto.UnidadeMedida}. O mínimo configurado é
                        <b>{produto.EstoqueMinimo}</b>.
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
        if (produto.Quantidade > produto.EstoqueMinimo)
        {
            produto.EmailEstoqueBaixoEnviado = false;
            produto.EmailProdutoZeradoEnviado = false;
        }

        _context.Movimentacoes.Add(mov);

        await _context.SaveChangesAsync();

        return Ok(mov);
    }
}
