namespace MyAuthentication.Models.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
    }
}
