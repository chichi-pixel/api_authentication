using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ApiKeyAuthentication.Authentication
{
    public class ApiKeyAuthMiddleware
    {
        private readonly RequestDelegate next;
        private readonly Microsoft.Extensions.Configuration.IConfiguration _configuration;
        private RequestDelegate _next;

        public ApiKeyAuthMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync (HttpContext context)
        {
            if(!context.Request.Headers.TryGetValue(AuthConstants.ApikeyHeaderName, out
                    var extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("API Key missing");
                return;
            }

            var ApiKey = _configuration.GetValue<string>(AuthConstants.ApiKeySectionName);
            if (!ApiKey.Equals(extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid API Key");
                return;
            }

            await _next(context);


        }
    }
}
