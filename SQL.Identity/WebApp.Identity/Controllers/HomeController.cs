using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApp.Identity.Models;

namespace WebApp.Identity.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<MyUser> _userManager;
        private readonly SignInManager<MyUser> _signInManager;
        private readonly IUserClaimsPrincipalFactory<MyUser> _userClaimsPrincipalFactory;

        public HomeController(UserManager<MyUser> userManager, SignInManager<MyUser> signInManager, IUserClaimsPrincipalFactory<MyUser> userClaimsPrincipalFactory)
        {
            this._userManager = userManager;
            this._signInManager = signInManager;
            this._userClaimsPrincipalFactory = userClaimsPrincipalFactory;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(Login model)
        {
            if (ModelState.IsValid)
            {
                #region Forma de Logar A
                var user = await _userManager.FindByNameAsync(model.UserName);
                var paswordCheck = await _userManager.CheckPasswordAsync(user, model.Password);
                var emailCheck = await _userManager.IsEmailConfirmedAsync(user);
                var lockCheck = await _userManager.IsLockedOutAsync(user);

                if (lockCheck == false)
                {
                    if (user != null)
                    {
                        if (paswordCheck == true)
                        {
                            if (emailCheck == true)
                            {
                                await _userManager.ResetAccessFailedCountAsync(user);

                                var principal = await _userClaimsPrincipalFactory.CreateAsync(user);

                                await HttpContext.SignInAsync("Identity.Application", principal);

                                return RedirectToAction("About");
                            }
                            else
                            {
                                ModelState.AddModelError("", "O Email não foi confirmado!");
                            }
                        }
                        else
                        {
                            ModelState.AddModelError("", "Senha inválida!");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Usuário inválido!");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Usuário bloqueado, aguarde...");

                    await _userManager.AccessFailedAsync(user);

                    //Enviar sugestão para troca de email aqui
                }
                #endregion

                #region Forma de Logar B
                //// Outra Forma de Logar
                // Salva o estado de login no cookie (manter logado após fechar browser) [true = manter | false = não manter]
                //var persistLogin = false;

                // Bloquear a conta do usuário após tentativas sem sucesso de logar [true = bloquear | false = não bloquear]
                //var lockUser = false;

                //var signInResult = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, persistLogin, lockUser);

                //if (signInResult.Succeeded)
                //{
                //    return RedirectToAction("About");
                //}
                #endregion
            }

            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(Register model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user == null)
                {
                    user = new MyUser()
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = model.UserName,
                        Email = model.UserName
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                        var confimationEmail = Url.Action("ConfirmEmailAddress", "Home",
                            new
                            {
                                token = token,
                                email = user.Email
                            }, Request.Scheme);

                        System.IO.File.WriteAllText("confirmationEmail.txt", confimationEmail);
                    }
                    else
                    {
                        foreach (var erro in result.Errors)
                        {
                            ModelState.AddModelError("", erro.Description);
                        }

                        return View();
                    }
                }

                return View("Success");
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmationEmailAsync(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    return View("Success");
                }
            }

            return View("Error");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPassword model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var resetUrl = Url.Action("ResetPassword", "Home",
                        new
                        {
                            token = token,
                            email = model.Email
                        }, Request.Scheme);

                    System.IO.File.WriteAllText("resetLink.txt", resetUrl);
                }
                else
                {
                    ModelState.AddModelError("", "E-mail inválido!");
                }
            }

            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var resetPassword = new ResetPassword();
            resetPassword.Token = token;
            resetPassword.Email = email;

            return View(resetPassword);
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPassword model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                    if (!result.Succeeded)
                    {
                        foreach (var erro in result.Errors)
                        {
                            ModelState.AddModelError("", erro.Description);
                        }

                        return View();
                    }

                    return View("Success");
                }

                ModelState.AddModelError("", "Invalid Request");
            }

            return View();
        }

        [HttpGet]
        [Authorize]
        public IActionResult About()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Success()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
