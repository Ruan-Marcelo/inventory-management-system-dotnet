using Microsoft.AspNetCore.Mvc;

namespace AuthUI.Controllers
{
    public class DashboardController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
