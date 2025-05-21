// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.Extensions.Logging;

namespace Hosts.Tests.TestInfra;

public class AutoFollowRedirectHandler(ILogger<AutoFollowRedirectHandler> logger) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var previousUri = request.RequestUri;
        for (var i = 0; i < 20; i++)
        {
            var result = await base.SendAsync(request, cancellationToken);
            if ((result.StatusCode == HttpStatusCode.Found || result.StatusCode == HttpStatusCode.RedirectKeepVerb) && result.Headers.Location != null)
            {
                logger.LogInformation("Redirecting from {0} to {1}", previousUri, result.Headers.Location);

                var newUri = result.Headers.Location;
                if (!newUri.IsAbsoluteUri)
                {
                    newUri = new Uri(previousUri!, newUri);
                }

                var headers = request.Headers;
                request = new HttpRequestMessage(HttpMethod.Get, newUri);
                foreach (var header in headers)
                {
                    request.Headers.Add(header.Key, header.Value);
                }

                previousUri = request.RequestUri;
                continue;
            }

            return result;
        }

        throw new InvalidOperationException("Keeps redirecting forever");
    }
}
