# AVA Manager

Sistema web desenvolvido para a AVA - Associação Vida Animal, com foco em gestão interna de estoque, controle de movimentações, alertas de insumos, usuários com perfis de acesso e apoio à rotina da clínica veterinária popular.

## Objetivo

O AVA Manager foi criado para centralizar processos que antes dependiam de controles manuais, ajudando a ONG a acompanhar produtos, medicamentos, materiais de limpeza, movimentações de entrada e saída, agendamentos do centro cirúrgico e relatórios operacionais.

A proposta atende ao programa **Desenvolvimento de Sistema Web**, com uma aplicação responsiva para uso em computadores, tablets e celulares.

## Instituição Beneficiária

- **Nome:** AVA - Associação Vida Animal
- **Tipo:** ONG
- **Endereço:** R. João Ramalho, 179 - Campos Elísios, Ribeirão Preto - SP
- **Missão:** democratizar o acesso a serviços veterinários por meio da Clínica Veterinária Popular e ações de proteção animal.

## Funcionalidades

- Autenticação com JWT.
- Perfis de acesso: `Admin`, `Funcionario` e `VeterinarioParceiro`.
- Logins temporários para veterinários parceiros, com data de expiração.
- Dashboard administrativo com indicadores de estoque, movimentações, valor em estoque e próximos agendamentos.
- Cadastro e gerenciamento de produtos.
- Categorias de produtos, como medicamentos, limpeza, alimentos e materiais cirúrgicos.
- Estoque mínimo configurável por produto.
- Alertas de estoque baixo e produto esgotado.
- Entrada e saída de produtos com histórico de movimentações.
- Inativação e reativação de produtos.
- Agendamento e controle da sala do centro cirúrgico.
- Relatórios de estoque e movimentações.
- Exportação CSV/Excel para apoio administrativo.
- Interface web responsiva.

## Tecnologias

- C#
- ASP.NET Core MVC
- ASP.NET Core Web API
- ASP.NET Core Identity
- JWT Bearer Authentication
- Entity Framework Core
- SQL Server
- Razor Views
- HTML, CSS e JavaScript
- Tailwind CSS via CDN
- Chart.js

## Estrutura do Projeto

```text
Authentication/
├── AuthAPI/        # Backend, autenticação, regras de negócio e banco
├── AuthUI/         # Frontend MVC/Razor
├── .vscode/        # Tasks para rodar API e UI juntas no VS Code
├── run-all.ps1     # Script para iniciar API e UI com um comando
└── Authentication.slnx
```

## Pré-requisitos

- .NET SDK 9 ou superior.
- SQL Server Express ou LocalDB.
- Visual Studio, Visual Studio Code ou terminal PowerShell.
- Certificado HTTPS de desenvolvimento do .NET.

Verifique a versão instalada:

```powershell
dotnet --version
```

Configure o certificado HTTPS local:

```powershell
dotnet dev-certs https --trust
```

## Configuração do Banco

A connection string fica em:

```text
AuthAPI/appsettings.json
```

Configuração atual:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=RUANZITO\\SQLEXPRESS;Database=AuthDb;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=true"
}
```

Se sua máquina usa LocalDB, troque para:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=AuthDb;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=true"
}
```

Se usa SQL Server Express local:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=localhost\\SQLEXPRESS;Database=AuthDb;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=true"
}
```

## Migrations

As migrations ficam em:

```text
AuthAPI/Migrations
```

Migrations existentes:

- `CreateIdentityTables`: cria as tabelas base do Identity.
- `ProdutoAtivo`: adiciona controle de produto ativo/inativo.
- `FixModels`: ajusta modelos de estoque e movimentações.
- `FixPreco`: ajusta precisão do preço.
- `EmailAlertas`: adiciona controle de alertas enviados.
- `AvaManagerCoreModules`: adiciona perfis temporários, categorias, estoque mínimo, centro cirúrgico e módulos principais.

Para aplicar as migrations e criar/atualizar o banco:

```powershell
dotnet ef database update --project AuthAPI\AuthAPI.csproj
```

Para criar uma nova migration após alterar modelos:

```powershell
dotnet ef migrations add NomeDaMigration --project AuthAPI\AuthAPI.csproj
```

Para remover a última migration ainda não aplicada:

```powershell
dotnet ef migrations remove --project AuthAPI\AuthAPI.csproj
```

## Usuário Inicial

Quando o sistema inicia e ainda não existe nenhum usuário, a API cria automaticamente um administrador:

```text
Email: admin@ava.local
Senha: Admin@123
Perfil: Admin
```

Depois do primeiro acesso, crie usuários reais pelo painel e altere/remova esse acesso padrão antes de usar em produção.

## Como Rodar

Na raiz do projeto:

```powershell
cd C:\Users\black\Downloads\Projetos\AVA\Authentication
```

Restaure e compile:

```powershell
dotnet restore
dotnet build Authentication.slnx
```

Aplique as migrations:

```powershell
dotnet ef database update --project AuthAPI\AuthAPI.csproj
```

Rode API e UI juntas:

```powershell
.\run-all.ps1
```

Endereços:

```text
Interface: https://localhost:7151
API:       https://localhost:7004
Swagger:   https://localhost:7004/swagger
```

## Rodar Pelo VS Code

Também é possível rodar tudo por task:

1. Abra o projeto no VS Code.
2. Pressione `Ctrl + Shift + P`.
3. Procure por `Tasks: Run Task`.
4. Escolha `Rodar API + UI`.
5. Acesse `https://localhost:7151`.

## Segurança

O sistema usa:

- Tokens JWT para autenticação da API.
- Rotas protegidas com `[Authorize]`.
- Perfis por role para separar permissões.
- Bloqueio de usuários inativos.
- Expiração de usuários temporários.
- Validações básicas de produto, estoque e agendamento.

Pontos importantes antes de produção:

- Alterar a chave JWT do `appsettings.json`.
- Remover credenciais reais do código e usar variáveis de ambiente ou user secrets.
- Configurar SMTP real em ambiente seguro.
- Trocar o usuário admin inicial.
- Publicar com HTTPS válido.

## Relatórios

O backend fornece endpoints de relatório em:

```text
GET /api/Relatorios/dashboard
GET /api/Relatorios/estoque
GET /api/Relatorios/estoque.csv
GET /api/Relatorios/movimentacoes
```

Esses relatórios apoiam:

- controle de estoque atual;
- produtos abaixo do mínimo;
- produtos esgotados;
- valor total estimado em estoque;
- histórico de entrada e saída;
- acompanhamento operacional da clínica.

## Fluxo Recomendado Para Desenvolvimento

1. Criar branch ou trabalhar em commits pequenos.
2. Alterar modelos e regras de negócio.
3. Criar migration quando houver alteração de banco.
4. Rodar `dotnet build Authentication.slnx`.
5. Aplicar migration com `dotnet ef database update`.
6. Testar login, estoque, movimentações e relatórios.
7. Fazer commit com mensagem clara.

## Status Atual

O projeto já cobre o núcleo do sistema descrito no documento:

- gestão de estoque;
- controle de usuários e permissões;
- alertas por nível mínimo;
- dashboard;
- relatórios;
- centro cirúrgico;
- responsividade web.

As próximas melhorias naturais são testes automatizados, publicação em servidor e configuração segura de e-mail em produção.
