// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;

namespace Duende.IdentityServer.Hosting.DynamicProviders;

internal class NopIdentityProviderStore : IIdentityProviderStore
{
    public Task<IEnumerable<IdentityProviderName>> GetAllSchemeNamesAsync() => Task.FromResult(Enumerable.Empty<IdentityProviderName>());

    public Task<IdentityProvider> GetBySchemeAsync(string scheme) => Task.FromResult<IdentityProvider>(null);
}
