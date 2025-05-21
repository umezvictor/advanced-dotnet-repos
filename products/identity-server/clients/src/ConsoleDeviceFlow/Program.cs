// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Diagnostics;
using Clients;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

// Add ServiceDefaults from Aspire
builder.AddServiceDefaults();

// Register named HttpClient with service discovery support.
// The AddServiceDiscovery extension enables Aspire to resolve the actual endpoint at runtime.
builder.Services.AddHttpClient("SimpleApi", client =>
{
    client.BaseAddress = new Uri("https://simple-api");
})
.AddServiceDiscovery();

// Build the host so we can resolve the HttpClientFactory.
var host = builder.Build();
var httpClientFactory = host.Services.GetRequiredService<IHttpClientFactory>();

// Resolve the authority from the configuration.
var authority = builder.Configuration["is-host"];

IDiscoveryCache _cache = new DiscoveryCache(authority);

var authorizeResponse = await RequestAuthorizationAsync();

var tokenResponse = await RequestTokenAsync(authorizeResponse);
tokenResponse.Show();

await CallServiceAsync(tokenResponse.AccessToken);

// Graceful shutdown
Environment.Exit(0);

async Task<DeviceAuthorizationResponse> RequestAuthorizationAsync()
{
    var disco = await _cache.GetAsync();
    if (disco.IsError)
    {
        throw new Exception(disco.Error);
    }

    var client = new HttpClient();
    var response = await client.RequestDeviceAuthorizationAsync(new DeviceAuthorizationRequest
    {
        Address = disco.DeviceAuthorizationEndpoint,
        ClientId = "device",
        ClientCredentialStyle = ClientCredentialStyle.PostBody
    });

    if (response.IsError)
    {
        throw new Exception(response.Error);
    }

    Console.WriteLine($"user code   : {response.UserCode}");
    Console.WriteLine($"device code : {response.DeviceCode}");
    Console.WriteLine($"URL         : {response.VerificationUri}");
    Console.WriteLine($"Complete URL: {response.VerificationUriComplete}");

    Process.Start(new ProcessStartInfo(response.VerificationUriComplete) { UseShellExecute = true });
    return response;
}

async Task<TokenResponse> RequestTokenAsync(DeviceAuthorizationResponse authorizeResponse)
{
    var disco = await _cache.GetAsync();
    if (disco.IsError)
    {
        throw new Exception(disco.Error);
    }

    var client = new HttpClient();

    while (true)
    {
        var response = await client.RequestDeviceTokenAsync(new DeviceTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "device",
            DeviceCode = authorizeResponse.DeviceCode
        });

        if (response.IsError)
        {
            if (response.Error == OidcConstants.TokenErrors.AuthorizationPending || response.Error == OidcConstants.TokenErrors.SlowDown)
            {
                Console.WriteLine($"{response.Error}...waiting.");
                Thread.Sleep(authorizeResponse.Interval * 1000);
            }
            else
            {
                throw new Exception(response.Error);
            }
        }
        else
        {
            return response;
        }
    }
}

async Task CallServiceAsync(string token)
{
    // Resolve the HttpClient from DI.
    var client = httpClientFactory.CreateClient("SimpleApi");

    client.SetBearerToken(token);
    var response = await client.GetStringAsync("identity");

    "\nService claims:".ConsoleGreen();
    Console.WriteLine(response.PrettyPrintJson());
}
