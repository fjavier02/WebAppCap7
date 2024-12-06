using Microsoft.AspNetCore.Mvc;
using WebAppCap7.Services;
using WebAppCap7.ViewModels;

namespace WebAppCap7.Controllers
{
    public class LoginController : Controller
    {
        private readonly UserService _userService;

        public LoginController(UserService userService)
        {
            _userService = userService;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Index(LoginInputViewModel model)
        {
            if (!ModelState.IsValid)
            {
                TempData["Message"] = "Datos inválidos. Por favor, intenta nuevamente.";
                return View(model);
            }

            var isValidUser = await _userService.ValidateUserAsync(model.Email, model.Password);
            if (isValidUser)
            {
                return RedirectToAction("Index", "Home"); // Redirige a la vista Home
            }
            else
            {
                TempData["Message"] = "Credenciales incorrectas. Por favor, intenta nuevamente.";
                return View(model); // Muestra de nuevo el formulario con el mensaje de error
            }
        }

        [HttpGet("login/auth")]
        public IActionResult Auth()
        {
            return Content("login");
        }
    }
}
