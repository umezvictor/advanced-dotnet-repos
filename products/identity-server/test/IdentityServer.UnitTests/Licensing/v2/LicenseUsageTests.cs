// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Licensing.V2;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Testing;

namespace IdentityServer.UnitTests.Licensing.V2;

public class LicenseUsageTests
{
    private IdentityServerOptions _options;
    private FakeLogger _logger;
    private LicenseUsageTracker _licenseUsageTracker;

    private void Init(string licenseKey)
    {
        _options = new IdentityServerOptions { LicenseKey = licenseKey };
        var licenseAccessor = new LicenseAccessor(_options, NullLogger<LicenseAccessor>.Instance);
        _logger = new FakeLogger();
        _licenseUsageTracker = new LicenseUsageTracker(licenseAccessor, new StubLoggerFactory(_logger));
    }

    [Fact]
    public void used_features_are_reported()
    {
        Init(null);

        _licenseUsageTracker.FeatureUsed(LicenseFeature.KeyManagement);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.PAR);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.ResourceIsolation);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.DynamicProviders);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.CIBA);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.ServerSideSessions);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.DPoP);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.DCR);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.ISV);
        _licenseUsageTracker.FeatureUsed(LicenseFeature.Redistribution);

        var summary = _licenseUsageTracker.GetSummary();

        summary.FeaturesUsed.ShouldContain(LicenseFeature.KeyManagement.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.PAR.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.ServerSideSessions.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.DCR.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.KeyManagement.ToString());

        summary.FeaturesUsed.ShouldContain(LicenseFeature.ResourceIsolation.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.DynamicProviders.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.CIBA.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.DPoP.ToString());

        summary.FeaturesUsed.ShouldContain(LicenseFeature.ISV.ToString());
        summary.FeaturesUsed.ShouldContain(LicenseFeature.Redistribution.ToString());
    }

    [Fact]
    public void used_clients_are_reported()
    {
        Init(null);

        _licenseUsageTracker.ClientUsed("mvc.code");
        _licenseUsageTracker.ClientUsed("mvc.dpop");

        var summary = _licenseUsageTracker.GetSummary();

        summary.ClientsUsed.Count.ShouldBe(2);
        summary.ClientsUsed.ShouldContain("mvc.code");
        summary.ClientsUsed.ShouldContain("mvc.dpop");
    }

    [Theory]
    [InlineData(TestLicenses.StarterLicense)]
    [InlineData(null)]
    public void client_count_within_limit_should_not_log(string licenseKey)
    {
        Init(licenseKey);

        for (var i = 0; i < 5; i++)
        {
            _licenseUsageTracker.ClientUsed($"client{i}");
        }

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    [Fact]
    public void client_count_over_limit_without_license_should_log_warning()
    {
        Init(null);

        for (var i = 0; i < 6; i++)
        {
            _licenseUsageTracker.ClientUsed("client" + i);
        }

        var initialLogSnapshot = _logger.Collector.GetSnapshot();
        initialLogSnapshot.ShouldContain(r =>
            r.Level == LogLevel.Error &&
            r.Message.StartsWith(
                "You do not have a license, and you have processed requests for 6 clients. This number requires a tier of license higher than Starter Edition. The clients used were:"));
    }

    [Fact]
    public void client_count_over_limit_and_within_overage_threshold_and_new_client_used_should_log_warning()
    {
        Init(TestLicenses.StarterLicense);

        for (var i = 0; i < 6; i++)
        {
            _licenseUsageTracker.ClientUsed($"client{i}");
        }

        var logSnapshot = _logger.Collector.GetSnapshot();
        logSnapshot.ShouldContain(r =>
            r.Level == LogLevel.Error &&
            r.Message.StartsWith(
                "Your license for Duende IdentityServer only permits 5 number of clients. You have processed requests for 6 clients and are still within the threshold of 5 for exceeding permitted clients. In a future version of client limit will be enforced. The clients used were:"));
    }

    [Fact]
    public void client_count_within_limit_and_existing_client_used_should_not_log_warning()
    {
        Init(TestLicenses.StarterLicense);

        for (var i = 0; i < 5; i++)
        {
            _licenseUsageTracker.ClientUsed($"client{i}");
        }

        _licenseUsageTracker.ClientUsed("client4");

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    [Fact]
    public void client_count_over_limit_and_over_threshold_overage_and_new_client_used_should_log_warning()
    {
        Init(TestLicenses.StarterLicense);

        for (var i = 0; i < 11; i++)
        {
            _licenseUsageTracker.ClientUsed($"client{i}");
        }

        var logSnapshot = _logger.Collector.GetSnapshot();
        logSnapshot.ShouldContain(r =>
            r.Level == LogLevel.Error &&
            r.Message.StartsWith("Your license for Duende IdentityServer only permits 5 number of clients. You have processed requests for 11 clients and are beyond the threshold of 5 for exceeding permitted clients. In a future version of client limit will be enforced. The clients used were:"));
    }

    [Fact]
    public void client_count_for_license_with_unlimited_clients_should_not_log_warning()
    {
        Init(TestLicenses.EnterpriseLicense);

        for (var i = 0; i < 11; i++)
        {
            _licenseUsageTracker.ClientUsed($"client{i}");
        }

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    [Fact]
    public void client_count_over_limit_for_redist_license_does_not_log()
    {
        Init(TestLicenses.RedistributionStarterLicense);

        for (var i = 0; i < 11; i++)
        {
            _licenseUsageTracker.ClientUsed($"client{i}");
        }

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    [Fact]
    public void used_issuers_are_reported()
    {
        Init(null);

        _licenseUsageTracker.IssuerUsed("https://localhost:5001");
        _licenseUsageTracker.IssuerUsed("https://acme.com");

        var summary = _licenseUsageTracker.GetSummary();

        summary.IssuersUsed.Count.ShouldBe(2);
        summary.IssuersUsed.ShouldContain("https://localhost:5001");
        summary.IssuersUsed.ShouldContain("https://acme.com");
    }

    [Theory]
    [InlineData(TestLicenses.StarterLicense)]
    [InlineData(null)]
    public void issuer_count_within_limit_should_not_log(string licenseKey)
    {
        Init(licenseKey);

        _licenseUsageTracker.IssuerUsed("issuer1");

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    [Fact]
    public void issuer_count_over_limit_without_license_should_log_warning()
    {
        Init(null);

        _licenseUsageTracker.IssuerUsed("issuer1");
        _licenseUsageTracker.IssuerUsed("issuer2");

        var initialLogSnapshot = _logger.Collector.GetSnapshot();
        initialLogSnapshot.ShouldContain(r =>
            r.Level == LogLevel.Error &&
            r.Message.StartsWith(
                $"You do not have a license, and you have processed requests for 2 issuers. If you are deliberately hosting multiple URLs then this number requires a license per issuer, or the Enterprise Edition tier of license. If not then this might be due to your server being accessed via different URLs or a direct IP and/or you have reverse proxy or a gateway involved, and this suggests a network infrastructure configuration problem. The issuers used were: "));
    }

    [Fact]
    public void issuer_count_over_limit_and_within_overage_threshold_and_new_client_used_should_log_warning()
    {
        Init(TestLicenses.StarterLicense);

        _licenseUsageTracker.IssuerUsed("issuer1");
        _licenseUsageTracker.IssuerUsed("issuer2");

        var logSnapshot = _logger.Collector.GetSnapshot();
        logSnapshot.ShouldContain(r =>
            r.Level == LogLevel.Error &&
            r.Message.StartsWith(
                "Your license for Duende IdentityServer only permits 1 number of issuers. You have processed requests for 2 issuers and are still within the threshold of 1. The issuers used were: ") &&
            r.Message.EndsWith(
                "This might be due to your server being accessed via different URLs or a direct IP and/or you have reverse proxy or a gateway involved. This suggests a network infrastructure configuration problem, or you are deliberately hosting multiple URLs and require an upgraded license. In a future version of issuer limit will be enforced."));
    }

    [Fact]
    public void issuer_count_within_limit_and_existing_client_used_should_not_log_warning()
    {
        Init(TestLicenses.StarterLicense);

        _licenseUsageTracker.IssuerUsed("issuer1");

        _licenseUsageTracker.ClientUsed("issuer1");

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    [Fact]
    public void issuer_count_over_limit_and_over_threshold_overage_and_new_client_used_should_log_warning()
    {
        Init(TestLicenses.StarterLicense);

        _licenseUsageTracker.IssuerUsed("issuer1");
        _licenseUsageTracker.IssuerUsed("issuer2");
        _licenseUsageTracker.IssuerUsed("issuer3");

        var logSnapshot = _logger.Collector.GetSnapshot();
        logSnapshot.ShouldContain(r =>
            r.Level == LogLevel.Error &&
            r.Message.StartsWith(
                "Your license for Duende IdentityServer only permits 1 number of issuers. You have processed requests for 3 issuers and are over the threshold of 1. The issuers used were: ") &&
            r.Message.EndsWith(
                "This might be due to your server being accessed via different URLs or a direct IP and/or you have reverse proxy or a gateway involved. This suggests a network infrastructure configuration problem, or you are deliberately hosting multiple URLs and require an upgraded license. In a future version of issuer limit will be enforced."));
    }

    [Fact]
    public void issuer_count_over_limit_for_redist_license_does_not_log()
    {
        Init(TestLicenses.RedistributionStarterLicense);

        _licenseUsageTracker.IssuerUsed("issuer1");
        _licenseUsageTracker.IssuerUsed("issuer2");
        _licenseUsageTracker.IssuerUsed("issuer3");

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    [Fact]
    public void issuer_count_for_license_with_unlimited_issuers_should_not_log_warning()
    {
        Init(TestLicenses.EnterpriseLicense);

        _licenseUsageTracker.IssuerUsed("issuer1");
        _licenseUsageTracker.IssuerUsed("issuer2");
        _licenseUsageTracker.IssuerUsed("issuer3");

        _logger.Collector.GetSnapshot().ShouldBeEmpty();
    }

    private static class TestLicenses
    {
        public const string StarterLicense =
            "eyJhbGciOiJQUzI1NiIsImtpZCI6IklkZW50aXR5U2VydmVyTGljZW5zZWtleS83Y2VhZGJiNzgxMzA0NjllODgwNjg5MTAyNTQxNGYxNiIsInR5cCI6ImxpY2Vuc2Urand0In0.eyJpc3MiOiJodHRwczovL2R1ZW5kZXNvZnR3YXJlLmNvbSIsImF1ZCI6IklkZW50aXR5U2VydmVyIiwiaWF0IjoxNzMwNDE5MjAwLCJleHAiOjE3MzE2Mjg4MDAsImNvbXBhbnlfbmFtZSI6Il90ZXN0IiwiY29udGFjdF9pbmZvIjoiam9lQGR1ZW5kZXNvZnR3YXJlLmNvbSIsImVkaXRpb24iOiJTdGFydGVyIiwiaWQiOiI2Njc3In0.WEEZFmwoSmJYVJ9geeSKvpB5GaJKQBUUFfABeeQEwh3Tkdg4gnjEme9WJS03MZkxMPj7nEfv8i0Tl1xwTC4gWpV2bfqDzj3R3eKCvz6BZflcmr14j4fbhbc7jDD26b5wAdyiD3krvkd2VsvVnYTTRCilK1UKr6ZVhmSgU8oXgth8JjQ2wIQ80p9D2nurHuWq6UdFdNqbO8aDu6C2eOQuAVmp6gKo7zBbFTbO1G1J1rGyWX8kXYBZMN0Rj_Xp_sdj34uwvzFsJN0i1EwhFATFS6vf6na_xpNz9giBNL04ulDRR95ZSE1vmRoCuP96fsgK7aYCJV1WSRBHXIrwfJhd7A";

        public const string EnterpriseLicense =
            "eyJhbGciOiJQUzI1NiIsImtpZCI6IklkZW50aXR5U2VydmVyTGljZW5zZWtleS83Y2VhZGJiNzgxMzA0NjllODgwNjg5MTAyNTQxNGYxNiIsInR5cCI6ImxpY2Vuc2Urand0In0.eyJpc3MiOiJodHRwczovL2R1ZW5kZXNvZnR3YXJlLmNvbSIsImF1ZCI6IklkZW50aXR5U2VydmVyIiwiaWF0IjoxNzMwNDE5MjAwLCJleHAiOjE3MzE2Mjg4MDAsImNvbXBhbnlfbmFtZSI6Il90ZXN0IiwiY29udGFjdF9pbmZvIjoiam9lQGR1ZW5kZXNvZnR3YXJlLmNvbSIsImVkaXRpb24iOiJFbnRlcnByaXNlIiwiaWQiOiI2Njg1In0.UgguIFVBciR8lpTF5RuM3FNcIm8m8wGR4Mt0xOCgo-XknFwXBpxOfr0zVjciGboteOl9AFtrqZLopEjsYXGFh2dkl5AzRyq--Ai5y7aezszlMpq8SkjRRCeBUYLNnEO41_YnfjYhNrcmb0Jx9wMomCv74vU3f8Hulz1ppWtoL-MVcGq0fhv_KOCP49aImCgiawPJ6a_bfs2C1QLpj-GG411OhdyrO9QLIH_We4BEvRUyajraisljB1VQzC8Q6188Mm_BLwl4ZENPaoNE4egiqTAuoTS5tb1l732-CGZwpGuU80NSpJbrUc6jd3rVi_pNf_1rH-O4Xt0HRCWiNCDYgg";

        public const string RedistributionStarterLicense =
            "eyJhbGciOiJQUzI1NiIsImtpZCI6IklkZW50aXR5U2VydmVyTGljZW5zZWtleS83Y2VhZGJiNzgxMzA0NjllODgwNjg5MTAyNTQxNGYxNiIsInR5cCI6ImxpY2Vuc2Urand0In0.eyJpc3MiOiJodHRwczovL2R1ZW5kZXNvZnR3YXJlLmNvbSIsImF1ZCI6IklkZW50aXR5U2VydmVyIiwiaWF0IjoxNzMwNDE5MjAwLCJleHAiOjE3MzE2Mjg4MDAsImNvbXBhbnlfbmFtZSI6Il90ZXN0IiwiY29udGFjdF9pbmZvIjoiY29udGFjdEBkdWVuZGVzb2Z0d2FyZS5jb20iLCJlZGl0aW9uIjoiU3RhcnRlciIsImlkIjoiNjY4MiIsImZlYXR1cmUiOiJpc3YiLCJwcm9kdWN0IjoiVEJEIn0.Ag4HLR1TVJ2VYgW1MJbpIHvAerx7zaHoM4CLu7baipsZVwc82ZkmLUeO_yB3CqN7N6XepofwZ-RcloxN8UGZ6qPRGQPE1cOMrp8YqxLOI38gJbxALOBG5BB6YTCMf_TKciXn1c3XhrsxVDayMGxAU68fKDCg1rnamBehZfXr2uENipNPkGDh_iuRw2MUgeGY96CGvwCC5R0E6UnvGZbjQ7dFYV-CkAHuE8dEAr0pX_gD77YsYcSxq5rNUavcNnWV7-3knFwozNqi02wTDpcKtqaL2mAr0nRof1E8Df9C8RwCTWXSaWhr9_47W2I1r_IhLYS2Jnq6m_3BgAIvWL4cjQ";
    }
}
