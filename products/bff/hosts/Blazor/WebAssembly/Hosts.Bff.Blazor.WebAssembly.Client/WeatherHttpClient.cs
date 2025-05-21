// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Net.Http.Json;
using System.Text.Json;

namespace Hosts.Bff.Blazor.WebAssembly.Client;

internal class WeatherHttpClient(HttpClient client)
{
    public async Task<WeatherForecast[]> GetWeatherForecasts() => await client.GetFromJsonAsync<WeatherForecast[]>("WeatherForecast")
                                                            ?? throw new JsonException("Failed to deserialize");
}
