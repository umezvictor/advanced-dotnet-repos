// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.Bff.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.Bff.Endpoints.SilentLogin;

/// <summary>
/// BFF specific OpenIdConnectEvents class.
/// </summary>
public class BffOpenIdConnectEvents(IOptions<BffOptions> options, ILogger<BffOpenIdConnectEvents> logger) : OpenIdConnectEvents
{
    /// <summary>
    /// The logger.
    /// </summary>
    protected readonly ILogger<BffOpenIdConnectEvents> Logger = logger;

    private object _silentRedirectUrl = "silent-redirect-url";

    /// <inheritdoc/>
    public override async Task RedirectToIdentityProvider(RedirectContext context)
    {
        if (!await ProcessRedirectToIdentityProviderAsync(context))
        {
            await base.RedirectToIdentityProvider(context);
        }
    }

    /// <summary>
    /// Processes the RedirectToIdentityProvider event.
    /// </summary>
    public virtual Task<bool> ProcessRedirectToIdentityProviderAsync(RedirectContext context)
    {
        if (context.Properties.IsSilentLogin())
        {
            var pathBase = context.Request.PathBase;
            var redirectPath = pathBase + options.Value.SilentLoginCallbackPath;

            context.Properties.RedirectUri = redirectPath;
            Logger.LogDebug("Setting OIDC ProtocolMessage.Prompt to 'none' for BFF silent login");
            context.ProtocolMessage.Prompt = "none";
        }
        else if (context.Properties.TryGetPrompt(out var prompt) == true)
        {
            Logger.LogDebug("Setting OIDC ProtocolMessage.Prompt to {prompt} for BFF silent login", prompt);
            context.ProtocolMessage.Prompt = prompt;
        }

        // we've not "handled" the request, so let other code process
        return Task.FromResult(false);
    }

    /// <inheritdoc/>
    public override async Task MessageReceived(MessageReceivedContext context)
    {
        if (!await ProcessMessageReceivedAsync(context))
        {
            await base.MessageReceived(context);
        }
    }

    /// <summary>
    /// Processes the MessageReceived event.
    /// </summary>
    public virtual Task<bool> ProcessMessageReceivedAsync(MessageReceivedContext context)
    {
        if (context.Properties?.IsSilentLogin() == true &&
            context.Properties?.RedirectUri != null)
        {
            context.HttpContext.Items["silent"] = context.Properties.RedirectUri;

            if (context.ProtocolMessage.Error != null)
            {
                Logger.LogDebug("Handling error response from OIDC provider for BFF silent login.");

                context.HandleResponse();
                context.Response.Redirect(context.Properties.RedirectUri);
                return Task.FromResult(true);
            }
        }
        else if (context.Properties?.TryGetPrompt(out _) == true &&
                 context.Properties?.RedirectUri != null)
        {
            if (context.ProtocolMessage.Error != null)
            {
                Logger.LogDebug("Handling error response from OIDC provider for BFF silent login.");

                context.HandleResponse();
                context.Response.Redirect(context.Properties.RedirectUri);
                return Task.FromResult(true);
            }
        }

        return Task.FromResult(false);
    }

    /// <inheritdoc/>
    public override async Task AuthenticationFailed(AuthenticationFailedContext context)
    {
        if (!await ProcessAuthenticationFailedAsync(context))
        {
            await base.AuthenticationFailed(context);
        }
    }

    /// <summary>
    /// Processes the AuthenticationFailed event.
    /// </summary>
    public virtual Task<bool> ProcessAuthenticationFailedAsync(AuthenticationFailedContext context)
    {
        if (!context.HttpContext.Items.ContainsKey(_silentRedirectUrl))
        {
            return Task.FromResult(false);
        }

        Logger.LogDebug("Handling failed response from OIDC provider for BFF silent login.");

        context.HandleResponse();
        context.Response.Redirect(context.HttpContext.Items[_silentRedirectUrl]!.ToString()!);

        return Task.FromResult(true);
    }
}
