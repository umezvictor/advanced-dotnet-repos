// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Duende.Bff.SessionManagement.Configuration;

/// <summary>
/// Cookie configuration for the user session plumbing
/// </summary>
internal class PostConfigureApplicationCookieTicketStore(
    IHttpContextAccessor httpContextAccessor,
    IOptions<AuthenticationOptions> options)
    : IPostConfigureOptions<CookieAuthenticationOptions>

{
    private readonly string? _scheme = options.Value.DefaultAuthenticateScheme ?? options.Value.DefaultScheme;

    /// <inheritdoc />
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        if (name == _scheme)
        {
            options.SessionStore = new TicketStoreShim(httpContextAccessor);
        }
    }
}
