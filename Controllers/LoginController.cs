using Microsoft.AspNetCore.Mvc;
using WebAppCap7.Services;
using WebAppCap7.ViewModels;

[Route("login")]
public class LoginController : Controller
{
    private readonly UserService _userService;

    public LoginController(UserService userService)
    {
        _userService = userService;
    }

    [HttpGet("")]
    public IActionResult Index()
    {
        return View();
    }

    [HttpPost("")]
    public async Task<IActionResult> Index(LoginInputViewModel model)
    {
        if (!ModelState.IsValid)
        {
            TempData["Message"] = "Dados inválidos. Por favor, tente novamente.";
            return View(model);
        }

        var userRole = await _userService.GetUserRoleAsync(model.Email, model.Password);
        if (!string.IsNullOrEmpty(userRole))
        {
            var token = await _userService.GenerateJwtTokenAsync(model.Email, userRole);

            HttpContext.Response.Cookies.Append("BearerToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(60)
            });

            return RedirectToAction("Index", "Home");
        }
        else
        {
            TempData["Message"] = "Credenciais incorretas. Por favor, tente novamente.";
            return View(model);
        }
    }

    [HttpGet("auth")]
    public IActionResult Auth()
    {
        return Content("login");
    }
}
