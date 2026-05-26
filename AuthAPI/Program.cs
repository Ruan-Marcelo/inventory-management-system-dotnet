using AuthAPI.Data;
using AuthAPI.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin", policy =>
    {
        policy.WithOrigins("https://localhost:7151", "http://localhost:5013")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

//identity configuration
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{

    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 0;

}).AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

//jwt configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        RoleClaimType = System.Security.Claims.ClaimTypes.Role,
        NameClaimType = System.Security.Claims.ClaimTypes.NameIdentifier,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key não configurada")))
    };
});

builder.Services.AddScoped<EmailService>();

var app = builder.Build();

await SeedIdentityAsync(app.Services);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/openapi/v1.json", "AuthAPI");
    });
}

app.UseCors("AllowSpecificOrigin");

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();

static async Task SeedIdentityAsync(IServiceProvider services)
{
    using var scope = services.CreateScope();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    string[] roles = ["Admin", "Funcionario", "VeterinarioParceiro"];

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }

    var admin = await userManager.FindByEmailAsync("admin@ava.local");

    if (admin == null)
    {
        admin = new ApplicationUser
        {
            UserName = "admin@ava.local",
            Email = "admin@ava.local",
            Name = "Administrador AVA",
            Perfil = "Admin",
            Ativo = true,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(admin, "Admin@123");

        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(admin, "Admin");
        }
    }
    else
    {
        admin.Name = string.IsNullOrWhiteSpace(admin.Name) ? "Administrador AVA" : admin.Name;
        admin.Perfil = "Admin";
        admin.Ativo = true;
        admin.ExpiraEm = null;
        admin.EmailConfirmed = true;

        await userManager.UpdateAsync(admin);

        if (!await userManager.IsInRoleAsync(admin, "Admin"))
        {
            await userManager.AddToRoleAsync(admin, "Admin");
        }
    }

    if (!db.Categorias.Any())
    {
        db.Categorias.AddRange(
            new AuthAPI.Models.Categoria { Nome = "Medicamentos", Descricao = "Remédios, vacinas e itens clínicos" },
            new AuthAPI.Models.Categoria { Nome = "Limpeza", Descricao = "Produtos de limpeza e higienização" },
            new AuthAPI.Models.Categoria { Nome = "Alimentos", Descricao = "Rações e alimentos" },
            new AuthAPI.Models.Categoria { Nome = "Materiais cirúrgicos", Descricao = "Itens usados em procedimentos" }
        );

        await db.SaveChangesAsync();
    }
}
