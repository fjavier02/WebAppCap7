using System.ComponentModel.DataAnnotations;

namespace WebAppCap7.ViewModels
{
    public class RegisterInputViewModel
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        [Required]
        [RegularExpression("ADMIN|USER", ErrorMessage = "El rol debe ser 'ADMIN' o 'USER'.")]
        public string Role { get; set; } = "user";
    }
}
