// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.Bff.Blazor.Client.Internals;

internal class BffClientAuthenticationStateProvider : AuthenticationStateProvider
{
    public const string HttpClientName = "Duende.Bff.Blazor.Client:StateProvider";

    private readonly FetchUserService _fetchUserService;
    private ITimer? _timer;
    private ClaimsPrincipal? _user;
    private readonly ILogger<BffClientAuthenticationStateProvider> _logger;

    private SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

    /// <summary>
    /// An <see cref="AuthenticationStateProvider"/> intended for use in Blazor
    /// WASM. It polls the /bff/user endpoint to monitor session state.
    /// </summary>
    public BffClientAuthenticationStateProvider(FetchUserService fetchUserService,
        PersistentUserService persistentUserService,
        TimeProvider timeProvider,
        IOptions<BffBlazorClientOptions> options,
        ILogger<BffClientAuthenticationStateProvider> logger)
    {
        _fetchUserService = fetchUserService;
        persistentUserService.GetPersistedUser(out var user);
        _user = user;
        _timer = timeProvider.CreateTimer(TimerCallback,
            null,
            TimeSpan.FromMilliseconds(options.Value.WebAssemblyStateProviderPollingDelay),
            TimeSpan.FromMilliseconds(options.Value.WebAssemblyStateProviderPollingInterval));
        _logger = logger;
    }

    private async void TimerCallback(object? _)
    {
        await _semaphore.WaitAsync();
        try
        {
            _user = await RefreshUser();
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task<ClaimsPrincipal> RefreshUser()
    {
        // We don't want to do any polling if we already know that the user is anonymous.
        // There's no way for us to become authenticated without the server issuing a cookie
        // and that can't happen while the WASM code is running.
        if (_user is { Identity.IsAuthenticated: false })
        {
            return _user;
        }

        var user = await _fetchUserService.FetchUserAsync();
        // Always notify that auth state has changed, because the user
        // management claims (usually) change over time. 
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));

        // If the session ended, then we can stop polling
        if (user.Identity!.IsAuthenticated == false)
        {
            if (_timer != null)
            {
                await _timer.DisposeAsync();
                _timer = null;
            }
        }

        return user;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        // There is a (theoretical) possibility that the timer and the GetAuthenticationStateAsync are fired
        // at the same time. We don't want any race conditions here. So, do a double locking pattern and only
        // refresh the user IF we don't already have a user.
        if (_user == null)
        {
            try
            {
                await _semaphore.WaitAsync();
                if (_user == null)
                {
                    _user = await RefreshUser();
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        return new AuthenticationState(_user);
    }
}
