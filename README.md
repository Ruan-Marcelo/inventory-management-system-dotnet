# Inventory Management System - .NET

Sistema de gerenciamento de estoque desenvolvido em ASP.NET Core .NET 9, utilizando autenticação JWT, ASP.NET Identity, Entity Framework Core e SQL Server.

O projeto possui:

* API REST (`AuthAPI`)
* Interface Web MVC (`AuthUI`)
* Controle de produtos
* Controle de categorias
* Movimentações de estoque
* Autenticação e autorização com JWT
* Integração com envio de e-mails
* Swagger/OpenAPI

---

# Tecnologias Utilizadas

* ASP.NET Core .NET 9
* ASP.NET Identity
* JWT Authentication
* Entity Framework Core
* SQL Server
* Razor Views (MVC)
* Swagger / OpenAPI
* HTML5
* CSS3
* JavaScript

---

# Estrutura do Projeto

```bash
Authentication/
│
├── AuthAPI/                 # API principal
│   ├── Controllers/
│   ├── Data/
│   ├── Migrations/
│   ├── Models/
│   ├── Services/
│   └── Program.cs
│
├── AuthUI/                  # Interface MVC
│   ├── Controllers/
│   ├── Models/
│   ├── Views/
│   ├── wwwroot/
│   └── Program.cs
│
└── SECURITY.md
```

---

# Funcionalidades

## Autenticação

* Cadastro de usuários
* Login com JWT
* ASP.NET Identity
* Controle de autorização
* Rotas protegidas com `[Authorize]`

## Produtos

* Cadastro de produtos
* Atualização de produtos
* Exclusão de produtos
* Listagem de produtos
* Controle de estoque
* Controle de produto ativo

## Categorias

* Cadastro de categorias
* Relacionamento entre categorias e produtos

## Movimentações

* Entrada de estoque
* Saída de estoque
* Histórico de movimentações
* Registro do usuário responsável

## E-mail

* Serviço de envio de e-mail
* Controle de alerta de estoque baixo

## Documentação

* Swagger/OpenAPI integrado

---

# Banco de Dados

O sistema utiliza SQL Server com Entity Framework Core.

Connection String encontrada no projeto:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=RUANZITO\\SQLEXPRESS;Database=AuthDb;Trusted_Connection=True;TrustServerCertificate=True"
}
```

---

# Configuração JWT

O projeto utiliza autenticação JWT.

Configuração presente no `appsettings.json`:

```json
"Jwt": {
  "Key": "YourSuperSecrerertyher4tgdgetegbfghg43547ahehgw46u35y35g5tergdfgdtrex45436ergtdyret43rdget43tgdfgert4etg4tKey",
  "Issuer": "YourIssuer",
  "Audience": "YourAudience",
  "ExpiryMinutes": 60
}
```

---

# Principais Controllers

## API

### `UserAuthController`

Responsável por:

* Registro de usuários
* Login
* Geração de token JWT

### `ProdutosController`

Responsável por:

* CRUD de produtos
* Controle de estoque

### `MovimentacoesController`

Responsável por:

* Entradas e saídas de estoque
* Histórico de movimentações
* Integração com e-mail

---

# Migrations Encontradas

O projeto já possui migrations configuradas:

* `CreateIdentityTables`
* `ProdutoAtivo`
* `FixModels`

---

# Como Executar o Projeto

## Pré-requisitos

* .NET 9 SDK
* SQL Server
* Visual Studio 2022+

---

## 1. Clonar o repositório

```bash
git clone https://github.com/Ruan-Marcelo/inventory-management-system-dotnet.git
```

---

## 2. Entrar na pasta do projeto

```bash
cd inventory-management-system-dotnet
```

---

## 3. Restaurar os pacotes

```bash
dotnet restore
```

---

## 4. Atualizar o banco de dados

Dentro da pasta `AuthAPI`:

```bash
dotnet ef database update
```

---

## 5. Executar a API

```bash
cd AuthAPI
dotnet run
```

---

## 6. Executar a interface MVC

```bash
cd AuthUI
dotnet run
```

---

# Swagger

A API possui Swagger configurado.

Após executar o projeto:

```bash
https://localhost:<porta>/swagger
```

---

# Segurança

O projeto possui:

* JWT Authentication
* ASP.NET Identity
* Rotas protegidas
* Controle de autorização
* Política de segurança documentada em `SECURITY.md`

---

# Interface Web

O projeto `AuthUI` utiliza ASP.NET MVC com Razor Views.

Views identificadas no projeto:

* Produtos
* Movimentações

---

# Dependências Encontradas

Pacotes identificados no projeto:

* Microsoft.AspNetCore.Authentication.JwtBearer
* Microsoft.AspNetCore.Identity.EntityFrameworkCore
* Microsoft.EntityFrameworkCore.SqlServer
* Swashbuckle.AspNetCore
* Microsoft.AspNetCore.OpenApi

---

# Objetivo do Projeto

O sistema foi desenvolvido para gerenciamento de estoque e autenticação de usuários utilizando tecnologias modernas do ecossistema .NET.

---

# Autor

## entity["people","Ruan Marcelo","Desenvolvedor Full Stack"]

GitHub:

urlRuan-Marcelo GitHub[https://github.com/Ruan-Marcelo](https://github.com/Ruan-Marcelo)

Projeto:

urlinventory-management-system-dotnet[https://github.com/Ruan-Marcelo/inventory-management-system-dotnet](https://github.com/Ruan-Marcelo/inventory-management-system-dotnet)

---

# Licença

Este projeto está disponível para fins de estudo e desenvolvimento.
