// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.Playwright;

namespace Hosts.Tests.PageModels;

public class PerComponentPageModel : BlazorModel
{
    public async Task<WebAssemblyPageModel> LogOut()
    {
        // Log out again
        await Page.GetByRole(AriaRole.Link, new() { Name = "Log Out" }).ClickAsync();

        var logoutPage = await Build<LogOutPageModel>();
        return await logoutPage.GoHome();
    }

    public async Task<CallApiPageModel> GoToCallApiPage()
    {
        await Page.GetByRole(AriaRole.Link, new() { Name = "Call Api" }).ClickAsync();

        return await Build<CallApiPageModel>();
    }
}

public class CallApiPageModel : PerComponentPageModel
{
    protected override async Task Verify() => await Expect(Page.GetByText("InteractiveServer")).ToBeVisibleAsync();

    public async Task InvokeCallApi(string headingName)
    {
        // Get the heading with the name "InteractiveServer"
        var heading = Page.GetByRole(AriaRole.Heading, new() { Name = headingName });

        // Get the parent div of the heading
        var parentDiv = heading.Locator("xpath=ancestor::div[@class='col']").First;

        // Assert that the parent div is found
        parentDiv.ShouldNotBeNull();

        var button = parentDiv.GetByRole(AriaRole.Button, new() { Name = "Call Api" });
        await button.ClickAsync();

        await Expect(parentDiv).ToContainTextAsync("Token ID");
    }
}
