using Microsoft.AspNetCore.Mvc;
using WebAppCap7.Helpers;
using WebAppCap7.Services;
using WebAppCap7.ViewModels;

namespace WebAppCap7.Controllers
{
    public class RegisterController : Controller
    {
        private readonly UserService _userService;

        public RegisterController(UserService userService)
        {
            _userService = userService;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Index(RegisterInputViewModel model)
        {
            if (!ModelState.IsValid)
            {
                TempData["Message"] = "Por favor, complete todos los campos correctamente.";
                return View(model);
            }

            // Encriptar la contraseña antes de guardar
            var encryptedPassword = EncryptionHelper.HashPassword(model.Password);

            // Guardar el usuario en la base de datos
            await _userService.AddUserAsync(model.Email, encryptedPassword, model.Role);

            TempData["Message"] = "Registro exitoso. Ahora puede iniciar sesión.";
            return RedirectToAction("Index", "Login");
        }
    }
}
