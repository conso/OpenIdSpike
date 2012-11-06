using System;
using System.Net;
using System.Web.Mvc;
using System.Web.Security;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth2;
using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.Extensions.SimpleRegistration;
using DotNetOpenAuth.OpenId.RelyingParty;
using OpenIdInnovation;

namespace MvcApplication1.Controllers
{
    public class AccountController : Controller
    {
        private AuthenticationProvider _authenticationProvider;
        private FacebookClient _facebookClient;

        public AccountController()
        {
            _authenticationProvider = new AuthenticationProvider();
            _facebookClient = new FacebookClient();
            _facebookClient.ClientIdentifier = "367977983289076";
            _facebookClient.ClientCredentialApplicator = ClientCredentialApplicator.PostParameter("2a78a6947f59f1e1c07ec50003ca5209");
        }




        public ActionResult LogOn()
        {
            var openid = new OpenIdRelyingParty();
            IAuthenticationResponse response = openid.GetResponse();

            var page = HttpContext.Items["page"] = "/";
            if (response != null)
            {
                switch (response.Status)
                {
                    case AuthenticationStatus.Authenticated:
                        FormsAuthentication.SetAuthCookie(response.GetExtension<ClaimsResponse>().Email, false);
                        return Redirect("~" + response.GetCallbackArgument("redirectPage"));
                        break;
                    case AuthenticationStatus.Canceled:
                        ModelState.AddModelError("loginIdentifier",
                            "Login was cancelled at the provider");
                        break;
                    case AuthenticationStatus.Failed:
                        ModelState.AddModelError("loginIdentifier",
                            "Login failed using the provided OpenID identifier");
                        break;
                }
            }

            return View();
        }

        [System.Web.Mvc.AcceptVerbs(HttpVerbs.Post)]
        public ActionResult LogOn(string loginIdentifier)
        {
            HttpContext.Items["page"] = "/";
            if (!Identifier.IsValid(loginIdentifier))
            {
                ModelState.AddModelError("loginIdentifier", "The specified login identifier is invalid");
                return View();
            }
            else
            {
                
                var openid = new OpenIdRelyingParty();
                var home = new Uri(@"http://localhost:55789/");
                IAuthenticationRequest request = openid.CreateRequest(Identifier.Parse(loginIdentifier));
                request.AddCallbackArguments("redirectPage", "/home/about");
                // Require some additional data
                request.AddExtension(new ClaimsRequest
                {
                    BirthDate = DemandLevel.NoRequest,
                    Email = DemandLevel.Require,
                    FullName = DemandLevel.Require
                });
                
                return request.RedirectingResponse.AsActionResult();
            }
        }
       

        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();

            return RedirectToAction("Index", "Home");
        }

      
     

      

       

        #region Status Codes
        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
        #endregion

        public ActionResult LogOnF()
        {
            IAuthorizationState authorization = _facebookClient.ProcessUserAuthorization();
            if (authorization == null)
            {
                // Kick off authorization request
                _facebookClient.PrepareRequestUserAuthorization(new string[] { "email" }, new Uri("http://localhost:55789/account/facebook")).Send();
                return _facebookClient.PrepareRequestUserAuthorization().AsActionResult();
            }
            return View("LogOn");
        }


        public ActionResult Facebook()
        {
            IAuthorizationState authorization = _facebookClient.ProcessUserAuthorization();
            if (authorization == null) return View("LogOn");
            var request = WebRequest.Create("https://graph.facebook.com/me?access_token=" + Uri.EscapeDataString(authorization.AccessToken));
            using (var response = request.GetResponse())
            {
                using (var responseStream = response.GetResponseStream())
                {
                    var graph = FacebookGraph.Deserialize(responseStream);

                    string myUserName = graph.Name;
                    string myEmail = graph.Email;
                    // use the data in the graph object to authorise the user
                    FormsAuthentication.SetAuthCookie(graph.Email, false);
                }
            }
            return RedirectToAction("About", "Home");
        }
         
    }
}
