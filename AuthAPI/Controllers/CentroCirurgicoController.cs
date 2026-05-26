using AuthAPI.Data;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AuthAPI.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class CentroCirurgicoController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public CentroCirurgicoController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IActionResult> Get([FromQuery] DateTime? inicio, [FromQuery] DateTime? fim)
        {
            var query = _context.AgendamentosCentroCirurgico.AsQueryable();

            if (inicio.HasValue)
            {
                query = query.Where(a => a.Inicio >= inicio.Value);
            }

            if (fim.HasValue)
            {
                query = query.Where(a => a.Inicio <= fim.Value);
            }

            var agendamentos = await query
                .OrderBy(a => a.Inicio)
                .ToListAsync();

            return Ok(agendamentos);
        }

        [HttpPost]
        [Authorize(Roles = "Admin,Funcionario,VeterinarioParceiro")]
        public async Task<IActionResult> Post([FromBody] AgendamentoCentroCirurgico agendamento)
        {
            var erro = await ValidarAgendamento(agendamento);
            if (erro != null)
            {
                return BadRequest(erro);
            }

            agendamento.UsuarioId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            agendamento.Status = NormalizarStatus(agendamento.Status);

            _context.AgendamentosCentroCirurgico.Add(agendamento);
            await _context.SaveChangesAsync();

            return Ok(agendamento);
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Admin,Funcionario,VeterinarioParceiro")]
        public async Task<IActionResult> Put(int id, [FromBody] AgendamentoCentroCirurgico agendamento)
        {
            var agendamentoDb = await _context.AgendamentosCentroCirurgico.FindAsync(id);

            if (agendamentoDb == null)
            {
                return NotFound("Agendamento não encontrado");
            }

            var erro = await ValidarAgendamento(agendamento, id);
            if (erro != null)
            {
                return BadRequest(erro);
            }

            agendamentoDb.Paciente = agendamento.Paciente.Trim();
            agendamentoDb.Procedimento = agendamento.Procedimento.Trim();
            agendamentoDb.VeterinarioResponsavel = agendamento.VeterinarioResponsavel.Trim();
            agendamentoDb.Inicio = agendamento.Inicio;
            agendamentoDb.Fim = agendamento.Fim;
            agendamentoDb.Status = NormalizarStatus(agendamento.Status);
            agendamentoDb.Observacao = agendamento.Observacao;

            await _context.SaveChangesAsync();

            return Ok(agendamentoDb);
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin,Funcionario")]
        public async Task<IActionResult> Delete(int id)
        {
            var agendamento = await _context.AgendamentosCentroCirurgico.FindAsync(id);

            if (agendamento == null)
            {
                return NotFound("Agendamento não encontrado");
            }

            _context.AgendamentosCentroCirurgico.Remove(agendamento);
            await _context.SaveChangesAsync();

            return Ok(new { mensagem = "Agendamento removido" });
        }

        private async Task<string?> ValidarAgendamento(AgendamentoCentroCirurgico agendamento, int? idAtual = null)
        {
            if (string.IsNullOrWhiteSpace(agendamento.Paciente))
                return "Paciente é obrigatório";

            if (string.IsNullOrWhiteSpace(agendamento.Procedimento))
                return "Procedimento é obrigatório";

            if (string.IsNullOrWhiteSpace(agendamento.VeterinarioResponsavel))
                return "Veterinário responsável é obrigatório";

            if (agendamento.Fim <= agendamento.Inicio)
                return "Horário final deve ser maior que o inicial";

            var status = NormalizarStatus(agendamento.Status);
            if (!new[] { "Agendado", "Realizado", "Cancelado" }.Contains(status))
                return "Status inválido";

            var temConflito = await _context.AgendamentosCentroCirurgico
                .AnyAsync(a =>
                    (!idAtual.HasValue || a.Id != idAtual.Value) &&
                    a.Status != "Cancelado" &&
                    status != "Cancelado" &&
                    agendamento.Inicio < a.Fim &&
                    agendamento.Fim > a.Inicio);

            if (temConflito)
                return "Já existe agendamento para este horário";

            agendamento.Paciente = agendamento.Paciente.Trim();
            agendamento.Procedimento = agendamento.Procedimento.Trim();
            agendamento.VeterinarioResponsavel = agendamento.VeterinarioResponsavel.Trim();

            return null;
        }

        private static string NormalizarStatus(string? status)
        {
            return string.IsNullOrWhiteSpace(status) ? "Agendado" : status.Trim();
        }
    }
}
