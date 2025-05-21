// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.Bff.AccessTokenManagement;
using Duende.Bff.Internal;
using Duende.Bff.Tests.TestHosts;
using Duende.Bff.Yarp;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Abstractions;

namespace Duende.Bff.Tests;

/// <summary>
/// These tests prove that you can use a custom IAccessTokenRetriever and that the context is populated correctly. 
/// </summary>
public class IAccessTokenRetriever_Extensibility_tests : BffIntegrationTestBase
{
    private ContextCapturingAccessTokenRetriever _customAccessTokenReceiver { get; } = new(NullLogger<DefaultAccessTokenRetriever>.Instance);

    public IAccessTokenRetriever_Extensibility_tests(ITestOutputHelper output) : base(output)
    {
        BffHost.OnConfigureServices += services =>
        {
            services.AddSingleton(_customAccessTokenReceiver);
        };

        BffHost.OnConfigure += app =>
        {
            app.UseEndpoints((endpoints) =>
            {
                endpoints.MapRemoteBffApiEndpoint("/custom", ApiHost.Url("/some/path"))
                    .RequireAccessToken()
                    .WithAccessTokenRetriever<ContextCapturingAccessTokenRetriever>();

            });

            app.Map("/subPath",
                subPath =>
                {
                    subPath.UseRouting();
                    subPath.UseEndpoints((endpoints) =>
                    {
                        endpoints.MapRemoteBffApiEndpoint("/custom_within_subpath", ApiHost.Url("/some/path"))
                            .RequireAccessToken()
                            .WithAccessTokenRetriever<ContextCapturingAccessTokenRetriever>();
                    });
                });

        };
    }

    [Fact]
    public async Task When_calling_custom_endpoint_then_AccessTokenRetrievalContext_has_api_address_and_localpath()
    {
        await BffHost.BffLoginAsync("alice");

        await BffHost.BrowserClient.CallBffHostApi(BffHost.Url("/custom"));

        var usedContext = _customAccessTokenReceiver.UsedContext.ShouldNotBeNull();

        usedContext.Metadata.RequiredTokenType.ShouldBe(TokenType.User);

        usedContext.ApiAddress.ShouldBe(new Uri(ApiHost.Url("/some/path")));
        usedContext.LocalPath.ToString().ShouldBe("/custom");

    }

    [Fact]
    public async Task When_calling_sub_custom_endpoint_then_AccessTokenRetrievalContext_has_api_address_and_localpath()
    {
        await BffHost.BffLoginAsync("alice");

        await BffHost.BrowserClient.CallBffHostApi(BffHost.Url("/subPath/custom_within_subpath"));

        var usedContext = _customAccessTokenReceiver.UsedContext.ShouldNotBeNull();

        usedContext.ApiAddress.ShouldBe(new Uri(ApiHost.Url("/some/path")));
        usedContext.LocalPath.ToString().ShouldBe("/custom_within_subpath");

    }

    /// <summary>
    /// Captures the context in which the access token retriever is called, so we can assert on it
    /// </summary>
    private class ContextCapturingAccessTokenRetriever : DefaultAccessTokenRetriever
    {
        public AccessTokenRetrievalContext? UsedContext { get; private set; }
        public ContextCapturingAccessTokenRetriever(ILogger<DefaultAccessTokenRetriever> logger) : base()
        {
        }

        public override Task<AccessTokenResult> GetAccessToken(AccessTokenRetrievalContext context)
        {
            UsedContext = context;
            return base.GetAccessToken(context);
        }
    }

}
