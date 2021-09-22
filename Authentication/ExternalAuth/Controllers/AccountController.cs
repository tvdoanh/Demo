using ExternalAuth.Data;
using ExternalAuth.Helpers;
using ExternalAuth.Models;
using ExternalAuth.ViewModels;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ExternalAuth.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IEventService _events;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IClientStore _clientStore;
        private readonly ILogger _logger;

        public AccountController(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IIdentityServerInteractionService interaction,
            IEventService events,
            IAuthenticationSchemeProvider schemeProvider,
            IClientStore clientStore,
            ILoggerFactory loggerFactory)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _interaction = interaction;
            _events = events;
            _schemeProvider = schemeProvider;
            _clientStore = clientStore;
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        #region Login
        // GET: /Account/Login
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LocalLoginViewModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, "Invalid login attempt");
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }
        #endregion


        #region External Authentication
        [HttpGet]
        [AllowAnonymous]
        public IActionResult External(string scheme, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

            // validate returnUrl - either it is a valid OIDC URL or back to a local page
            if (Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            {
                // user might have clicked on a malicious link - should be logged
                throw new Exception("invalid return URL");
            }

            // start challenge and roundtrip the return URL and scheme 
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(Callback)),
                Items =
                {
                    { "returnUrl", returnUrl },
                    { "scheme", scheme },
                }
            };

            return Challenge(props, scheme);
        }


        // Callback
        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                var externalClaims = result.Principal.Claims.Select(c => $"{c.Type}: {c.Value}");
                _logger.LogDebug("External claims: {@claims}", externalClaims);
            }

            // lookup our user and external provider info
            var (user, provider, providerUserId, claims) = await FindUserFromExternalProviderAsync(result);
            if (user == null)
            {
                // this might be where you might initiate a custom workflow for user registration
                // in this sample we don't show how that would be done, as our sample implementation
                // simply auto-provisions new external user
                user = await AutoProvisionUserAsync(provider, providerUserId, claims);
            }

            // this allows us to collect any additional claims or properties
            // for the specific protocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            ProcessLoginCallback(result, additionalLocalClaims, localSignInProps);

            // issue authentication cookie for user
            // we must issue the cookie maually, and can't use the SignInManager because
            // it doesn't expose an API to issue additional claims from the login workflow
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            additionalLocalClaims.AddRange(principal.Claims);
            var name = principal.FindFirst(JwtClaimTypes.Name)?.Value ?? user.Id;

            var isuser = new IdentityServerUser(user.Id)
            {
                DisplayName = name,
                IdentityProvider = provider,
                AdditionalClaims = additionalLocalClaims
            };

            await HttpContext.SignInAsync(isuser, localSignInProps);

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // retrieve return URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            // check if external login is in the context of an OIDC request
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id, name, true, context?.Client.ClientId));

            if (context != null)
            {
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage("Redirect", returnUrl);
                }
            }

            return Redirect(returnUrl);
        }

        private async Task<(ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims)>
            FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // find external user
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }


        private async Task<ApplicationUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            // create a list of claims that we want to transfer into our store
            var filtered = new List<Claim>();

            // user's display name
            var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ??
                claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            if (name != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, name));
            }
            else
            {
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
                if (first != null && last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
                }
                else if (first != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first));
                }
                else if (last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, last));
                }
            }

            // email
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
               claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;

            if (email != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, email));
            }

            var user = new ApplicationUser
            {
                DisplayName = name,
                UserName = email,
                Email = email,
            };

            var identityResult = await _userManager.CreateAsync(user);
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            if (filtered.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(user, filtered);
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            return user;
        }

        // if the external login is OIDC-based, there are certain things we need to preserve to make logout work
        // this will be different for WS-Fed, SAML2p or other protocols
        private void ProcessLoginCallback(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var idToken = externalResult.Properties.GetTokenValue("id_token");
            if (idToken != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
            }
        }
        #endregion


        #region Logout
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModel(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        // POST: /Account/Logout
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutViewModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModel(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }
        #endregion





        #region Helpers

        // Build Login
        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LocalLoginViewModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        // Logout
        private async Task<LogoutViewModel> BuildLogoutViewModel(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModel(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        // Add Errors
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        // Redirect to Local
        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }
        #endregion
    }
}
