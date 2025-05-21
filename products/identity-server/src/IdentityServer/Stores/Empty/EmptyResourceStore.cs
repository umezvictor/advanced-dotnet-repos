// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using Duende.IdentityServer.Models;

namespace Duende.IdentityServer.Stores.Empty;

internal class EmptyResourceStore : IResourceStore
{
    public Task<IEnumerable<ApiResource>> FindApiResourcesByNameAsync(IEnumerable<string> apiResourceNames) => Task.FromResult(Enumerable.Empty<ApiResource>());

    public Task<IEnumerable<ApiResource>> FindApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames) => Task.FromResult(Enumerable.Empty<ApiResource>());

    public Task<IEnumerable<ApiScope>> FindApiScopesByNameAsync(IEnumerable<string> scopeNames) => Task.FromResult(Enumerable.Empty<ApiScope>());

    public Task<IEnumerable<IdentityResource>> FindIdentityResourcesByScopeNameAsync(IEnumerable<string> scopeNames) => Task.FromResult(Enumerable.Empty<IdentityResource>());

    public Task<Resources> GetAllResourcesAsync() => Task.FromResult(new Resources() { OfflineAccess = true });
}
