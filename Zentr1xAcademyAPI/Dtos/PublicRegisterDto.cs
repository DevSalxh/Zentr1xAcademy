namespace Zentr1xAcademyAPI.Dtos
{
    public class PublicRegisterDto
    {
        public string FirstName { get; set; } = string.Empty;
        public string MiddleName { get; set; } = string.Empty;  // Optional
        public string LastName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty ;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public DateTime Birthday { get; set; }
        public string PhoneNumber { get; set; } = string.Empty;
    }

}
