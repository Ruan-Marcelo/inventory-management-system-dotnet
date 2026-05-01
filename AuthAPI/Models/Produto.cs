using Microsoft.AspNetCore.Mvc;

namespace AuthAPI.Models
{
    public class Produto : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
