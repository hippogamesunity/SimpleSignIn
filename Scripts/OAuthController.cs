using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PixelNetwork.Properties;

namespace PixelNetwork.Controllers
{
	/// <summary>
	/// OAuthController should be deployed as a part of your ASP.NET website.
	/// It may contain insignificant dependencies to other parts of the original Authorization Middleware, just comment or replace them.
	/// Alternatively, you can use it as a reference and implement the same logic with other programming languages and platforms.
	/// </summary>
    [Route("api/[controller]")]
    public class OAuthController : BaseController
    {
        private static readonly Dictionary<string, string> Redirects = new Dictionary<string, string>();
        private static readonly Dictionary<string, string> Codes = new Dictionary<string, string>();

        [HttpPost("init")]
        public void Init(string state, string redirectUri, string clientName)
        {
            if (state == null) throw new Exception("Invalid parameters.");
            if (Redirects.Count >= 1000) Redirects.Remove(Redirects.Keys.First());
            if (Redirects.ContainsKey(state)) Redirects.Remove(state);

            Redirects.Add(state, redirectUri);
            Event("Init", "RedirectUri", redirectUri, "ClientName", clientName);
        }

        [HttpGet("redirect")]
        public IActionResult Redirect(string code, string state)
        {
            if (code == null || state == null) throw new Exception("Invalid parameters.");
            if (!Redirects.ContainsKey(state)) throw new Exception("Unexpected state.");
            if (Codes.Count >= 1000) Codes.Remove(Redirects.Keys.First());
            if (Codes.ContainsKey(state)) Codes.Remove(state);

            var redirectUri = Redirects[state];

            Redirects.Remove(state);

            if (string.IsNullOrEmpty(redirectUri))
            {
                Codes.Add(state, code);
            }
            else
            {
                Response.Redirect($"{redirectUri}?code={code}&state={state}", permanent: true);
            }

            var template = Request.Headers.TryGetValue("Referer", out var referer) && (referer.Contains("https://id.vk.com/") || referer.Contains("https://twitter.com/") || referer.Contains("/telegramwidget") || referer.Contains("https://appleid.apple.com/"))
                ? Resources.OAuthTemplate
                : Resources.OAuthTemplateAutoClosed;

            if (Request.GetDisplayUrl().Contains("platform=telegram"))
            {
                template = Resources.OAuthTemplate;
            }

            return Content(template, "text/html", Encoding.UTF8);
        }

        [HttpPost("get_code"), HttpPost("getcode")]
        public IActionResult GetCode(string state)
        {
            if (state == null) throw new Exception("Invalid parameters.");
            if (!Codes.ContainsKey(state)) return StatusCode(704);

            var code = Codes[state];

            Codes.Remove(state);

            return Content(code);
        }

        [HttpPost("download")]
        public IActionResult Download(string url)
        {
            if (!url.StartsWith("https://oauth.vk.com/access_token") && !url.StartsWith("https://api.vk.com/method/users.get")) 
                throw new Exception("Unsupported url.");

            return Content(new HttpClient().GetStringAsync(url).Result);
        }

        [HttpPost("apple_redirect")]
        public IActionResult AppleRedirect(string code, string id_token, string state, string user)
        {
            if (code == null || state == null) throw new Exception("Invalid parameters.");

            code = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new { code, user = user == null ? null : JObject.Parse(user) })));

            return Redirect(code, state);
        }

        [HttpGet("telegram_auth")]
        public IActionResult TelegramAuth(string id, string state, int widget)
        {
            var html = widget == 1
                ? "<html><body><div style='display: flex; justify-content: center; align-items: center; height: 200px;'><script async src='https://telegram.org/js/telegram-widget.js?22' data-telegram-login='{id}' data-size='large' data-onauth='onTelegramAuth(user)' data-request-access='write'></script><script type='text/javascript'>function onTelegramAuth(user) { location.href='https://hippogames.dev/api/oauth/redirect?platform=telegram&state={state}&code=' + btoa(JSON.stringify(user)); }</script></div></body></html>"
                : "<html><body><script src='https://telegram.org/js/telegram-widget.js'></script><script>window.Telegram.Login.auth({ bot_id: '{id}', request_access: true }, (data) => { window.location.href = 'https://hippogames.dev/api/oauth/redirect?platform=telegram&state={state}&code=' + btoa(JSON.stringify(data)); });</script></body></html>";

            html = html.Replace("{id}", id);
            html = html.Replace("{state}", state);

            return Content(html, "text/html", Encoding.UTF8);
        }
    }
}