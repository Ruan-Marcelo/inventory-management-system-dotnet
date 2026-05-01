using Microsoft.AspNetCore.Mvc;

namespace AuthUI.Controllers
{
    public class StockMovementsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
