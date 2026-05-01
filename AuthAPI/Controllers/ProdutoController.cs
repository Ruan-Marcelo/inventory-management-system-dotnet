using Microsoft.AspNetCore.Mvc;

namespace AuthUI.Controllers
{
    public class ProdutoController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
