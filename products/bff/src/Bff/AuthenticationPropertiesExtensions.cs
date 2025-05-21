// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;


namespace Duende.Bff;

/// <summary>
///  Extension methods for AuthenticationProperties
/// </summary>
public static class AuthenticationPropertiesExtensions
{
    /// <summary>
    /// Determines if this AuthenticationProperties represents a BFF silent login.
    /// </summary>
    public static bool IsSilentLogin(this AuthenticationProperties props) => props.TryGetPrompt(out var prompt) && prompt == "none";

    public static bool TryGetPrompt(this AuthenticationProperties props, [NotNullWhen(true)] out string? prompt) => props.Items.TryGetValue(Constants.BffFlags.Prompt, out prompt);
}
