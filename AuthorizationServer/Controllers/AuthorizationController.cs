using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer.Controllers
{
    public class AuthorizationController : Controller
    {
        [HttpGet("~/connect/authorize")]
        public async Task<IActionResult> Authorize(OpenIdConnectRequest request)
        {
            Debug.Assert(request.IsAuthorizationRequest(),
                "The OpenIddict binder for ASP.NET Core MVC is not registered. " +
                "Make sure services.AddOpenIddict().AddMvcBinders() is correctly called.");

            // Check if a user is authenticated. If not, challenge the GitHub authentication handler
            if (!User.Identity.IsAuthenticated)
                return Challenge("GitHub");

            // Create a new ClaimsPrincipal containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity("OpenIddict");
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, User.FindFirstValue(ClaimTypes.NameIdentifier), 
                OpenIdConnectConstants.Destinations.AccessToken, OpenIdConnectConstants.Destinations.IdentityToken);
            identity.AddClaim(OpenIdConnectConstants.Claims.Name, User.FindFirstValue(ClaimTypes.Name),
                OpenIdConnectConstants.Destinations.IdentityToken);
            identity.AddClaim(OpenIdConnectConstants.Claims.Email, User.FindFirstValue(ClaimTypes.Email),
                OpenIdConnectConstants.Destinations.IdentityToken);
            identity.AddClaim(OpenIdConnectConstants.Claims.EmailVerified, "true",
                OpenIdConnectConstants.Destinations.IdentityToken); // We'll assume email is verified since we get it from GitHub
            identity.AddClaim(OpenIdConnectConstants.Claims.Picture, User.FindFirstValue("github:avatar"),
                OpenIdConnectConstants.Destinations.IdentityToken);
            var principal = new ClaimsPrincipal(identity);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(principal,
                new AuthenticationProperties(), 
                OpenIdConnectServerDefaults.AuthenticationScheme);
            
            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }
    }
}