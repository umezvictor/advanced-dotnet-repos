// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

namespace Hosts.Bff.Blazor.PerComponent.Client;

public class ClientRenderModeContext : IRenderModeContext
{
    public RenderMode GetMode() => RenderMode.Client;
}
