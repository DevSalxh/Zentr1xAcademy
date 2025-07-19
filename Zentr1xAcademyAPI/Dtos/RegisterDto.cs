namespace Zentr1xAcademyAPI.Dtos
{
    public class RegisterDto
    {
        public string FirstName { get; set; } = string.Empty;
        public string MiddleName { get; set; } = string.Empty;  // Optional
        public string LastName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty ;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty; // Admin, Instructor, Student
        public DateTime Birthday { get; set; }
        public string PhoneNumber { get; set; } = string.Empty;
    }

}
