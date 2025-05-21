// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Diagnostics.Metrics;
using System.Security.Claims;
using Duende.AccessTokenManagement.OpenIdConnect;
using Duende.Bff.Blazor;
using Duende.Bff.Internal;
using Duende.Bff.SessionManagement.SessionStore;
using Duende.Bff.SessionManagement.TicketStore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Bff.Tests.Blazor;

public class ServerSideTokenStoreTests
{
    private ClaimsPrincipal CreatePrincipal(string sub, string sid) => new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", sub),
            new Claim("sid", sid)
        ], "pwd", "name", "role"));

    [Fact]
    public async Task Can_add_retrieve_and_remove_tokens()
    {
        var user = CreatePrincipal("sub", "sid");
        var props = new AuthenticationProperties();
        var expectedToken = new UserToken()
        {
            AccessToken = "expected-access-token"
        };

        // Create shared dependencies
        var sessionStore = new InMemoryUserSessionStore();
        var dataProtection = new EphemeralDataProtectionProvider();

        // Use the ticket store to save the user's initial session
        // Note that we don't yet have tokens in the session
        var sessionService = new ServerSideTicketStore(new BffMetrics(new DummyMeterFactory()), sessionStore, dataProtection, new NullLogger<ServerSideTicketStore>());
        await sessionService.StoreAsync(new AuthenticationTicket(
            user,
            props,
            "test"
        ));

        var tokensInProps = MockStoreTokensInAuthProps();

        var sut = new ServerSideTokenStore(
            tokensInProps,
            sessionStore,
            dataProtection,
            new NullLogger<ServerSideTokenStore>(),
            Substitute.For<AuthenticationStateProvider, IHostEnvironmentAuthenticationStateProvider>());


        await sut.StoreTokenAsync(user, expectedToken);
        var actualToken = await sut.GetTokenAsync(user);

        actualToken.ShouldNotBe(null);
        actualToken.AccessToken.ShouldBe(expectedToken.AccessToken);

        await sut.ClearTokenAsync(user);

        var resultAfterClearing = await sut.GetTokenAsync(user);
        resultAfterClearing.AccessToken.ShouldBeNull();
    }

    private static StoreTokensInAuthenticationProperties MockStoreTokensInAuthProps()
    {
        var tokenManagementOptionsMonitor = Substitute.For<IOptionsMonitor<UserTokenManagementOptions>>();
        var tokenManagementOptions = new UserTokenManagementOptions { UseChallengeSchemeScopedTokens = false };
        tokenManagementOptionsMonitor.CurrentValue.Returns(tokenManagementOptions);

        var cookieOptionsMonitor = Substitute.For<IOptionsMonitor<CookieAuthenticationOptions>>();
        var cookieAuthenticationOptions = new CookieAuthenticationOptions();
        cookieOptionsMonitor.CurrentValue.Returns(cookieAuthenticationOptions);

        var schemeProvider = Substitute.For<IAuthenticationSchemeProvider>();
        schemeProvider.GetDefaultSignInSchemeAsync().Returns(new AuthenticationScheme("TestScheme", null, typeof(IAuthenticationHandler)));

        return new StoreTokensInAuthenticationProperties(
            tokenManagementOptionsMonitor,
            cookieOptionsMonitor,
            schemeProvider,
            Substitute.For<ILogger<StoreTokensInAuthenticationProperties>>());
    }

    private class DummyMeterFactory : IMeterFactory
    {
        public void Dispose()
        {
        }

        public Meter Create(MeterOptions options) => new Meter(options);
    }

}
