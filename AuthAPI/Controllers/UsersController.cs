using Microsoft.AspNetCore.Mvc;

namespace AuthUI.Controllers
{
    public class UsersController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
