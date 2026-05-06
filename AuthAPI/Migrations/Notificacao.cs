namespace AuthAPI.Migrations
{
    public class Notificacao
    {
        public int Id { get; set; }
        public string Mensagem { get; set; }
        public DateTime Data { get; set; }
        public bool Lida { get; set; }
    }
}
