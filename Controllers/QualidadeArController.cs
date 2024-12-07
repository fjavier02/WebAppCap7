using Microsoft.AspNetCore.Mvc;

namespace WebAppCap7.Controllers
{
    public class QualidadeArController : Controller
    {
        private readonly DatabaseContext _context;

        public QualidadeArController(DatabaseContext context)
        {
            _context = context;
        }

        public IActionResult Index()
        {
            var qualidades = _context.QualidadeAr.ToList(); 
            return View(qualidades);
        }
    }
}