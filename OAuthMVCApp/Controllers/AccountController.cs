using System.Web.Mvc;
using Microsoft.Owin.Security;
using System.Web;

namespace OAuthMVCApp.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login()
        {
            if (!Request.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/" },
                    "OpenIdConnect"
                );
                return new HttpUnauthorizedResult();
            }
            return RedirectToAction("Index", "Home");
        }

        // Initiate Logout
        public ActionResult Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(
                "Cookies",
                "OpenIdConnect"
            );
            return RedirectToAction("Index", "Home");
        }

        // Handle Unauthorized Access
        public ActionResult Unauthorized()
        {
            return View();
        }
    }
}
