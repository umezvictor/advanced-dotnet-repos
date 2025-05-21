// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using NSubstitute;

namespace Duende.AspNetCore.Authentication.JwtBearer.DPoP;

public class ReplayTests : DPoPProofValidatorTestBase
{
    [Fact]
    [Trait("Category", "Unit")]
    public async Task replays_detected_in_ValidateReplay_fail()
    {
        ReplayCache.Exists(TokenIdHash).Returns(true);
        Result.TokenIdHash = TokenIdHash;

        await ProofValidator.ValidateReplay(Context, Result);

        Result.ShouldBeInvalidProofWithDescription("Detected DPoP proof token replay.");
    }

    [Theory]
    [Trait("Category", "Unit")]
    [InlineData(true, false, ClockSkew, 0)]
    [InlineData(false, true, 0, ClockSkew)]
    [InlineData(true, true, ClockSkew, ClockSkew * 2)]
    [InlineData(true, true, ClockSkew * 2, ClockSkew)]
    [InlineData(true, true, ClockSkew * 2, ClockSkew * 2)]
    public async Task new_proof_tokens_are_added_to_replay_cache(bool validateIat, bool validateNonce, int clientClockSkew, int serverClockSkew)
    {
        ReplayCache.Exists(TokenIdHash).Returns(false);

        Options.ValidationMode = (validateIat && validateNonce) ? ExpirationValidationMode.Both
            : validateIat ? ExpirationValidationMode.IssuedAt : ExpirationValidationMode.Nonce;
        Options.ClientClockSkew = TimeSpan.FromSeconds(clientClockSkew);
        Options.ServerClockSkew = TimeSpan.FromSeconds(serverClockSkew);
        Options.ProofTokenValidityDuration = TimeSpan.FromSeconds(ValidFor);

        Result.TokenIdHash = TokenIdHash;

        await ProofValidator.ValidateReplay(Context, Result);

        Result.IsError.ShouldBeFalse();
        var skew = validateIat && validateNonce
            ? Math.Max(clientClockSkew, serverClockSkew)
            : (validateIat ? clientClockSkew : serverClockSkew);
        var expectedExpiration = ProofValidator.TestTimeProvider.GetUtcNow()
            .Add(TimeSpan.FromSeconds(skew * 2))
            .Add(TimeSpan.FromSeconds(ValidFor));
        await ReplayCache.Received().Add(TokenIdHash, expectedExpiration);
    }
}
