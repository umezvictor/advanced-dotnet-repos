// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.Playwright;

namespace Hosts.Tests.PageModels;

public class LogOutPageModel : PageModel
{
    public async Task<WebAssemblyPageModel> GoHome()
    {
        await Page.GetByRole(AriaRole.Link, new() { Name = "here" }).ClickAsync();

        return await Build<WebAssemblyPageModel>();
    }
}
