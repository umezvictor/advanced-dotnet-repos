// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Hosts.Bff.Blazor.PerComponent.Client;

namespace Hosts.Bff.Blazor.PerComponent;

public class ServerRenderModeContext(IHttpContextAccessor accessor) : IRenderModeContext
{
    RenderMode IRenderModeContext.GetMode()
    {
        var prerendering = !accessor.HttpContext?.Response.HasStarted ?? false;
        if (prerendering)
        {
            return RenderMode.Prerender;
        }
        else
        {
            return RenderMode.Server;
        }

    }
}
