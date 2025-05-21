// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

#nullable enable

namespace Duende.IdentityServer.Licensing.V2;

internal static class LicenseUsageTrackerExtensions
{
    internal static void ResourceIndicatorUsed(this LicenseUsageTracker tracker, string? resourceIndicator)
    {
        if (!string.IsNullOrWhiteSpace(resourceIndicator))
        {
            tracker.FeatureUsed(LicenseFeature.ResourceIsolation);
        }
    }

    internal static void ResourceIndicatorsUsed(this LicenseUsageTracker tracker, IEnumerable<string> resourceIndicators)
    {
        if (resourceIndicators?.Any() == true)
        {
            tracker.FeatureUsed(LicenseFeature.ResourceIsolation);
        }
    }
}
