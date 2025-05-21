// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


namespace Duende.IdentityServer.Services.KeyManagement;

/// <summary>
/// Interface to model caching keys loaded from key store.
/// </summary>
public interface ISigningKeyStoreCache
{
    /// <summary>
    /// Returns cached keys.
    /// </summary>
    /// <returns></returns>
    Task<IEnumerable<KeyContainer>> GetKeysAsync();

    /// <summary>
    /// Caches keys for duration.
    /// </summary>
    /// <param name="keys"></param>
    /// <param name="duration"></param>
    /// <returns></returns>
    Task StoreKeysAsync(IEnumerable<KeyContainer> keys, TimeSpan duration);
}
