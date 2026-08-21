using BTCPayServer.Abstractions.Contracts;
using BTCPayServer.Abstractions.Models;
using Microsoft.Extensions.DependencyInjection;

namespace BTCPayServer.Plugins.NostrLogin;

public class Plugin : BaseBTCPayServerPlugin
{
    public override IBTCPayServerPlugin.PluginDependency[] Dependencies { get; } =
    {
        new IBTCPayServerPlugin.PluginDependency { Identifier = nameof(BTCPayServer), Condition = ">=2.4.2" }
    };

    public override void Execute(IServiceCollection services)
    {
        services.AddSingleton<NostrLoginService>();
        services.AddSingleton<NostrProfilePictureService>();
        services.AddHttpClient();
        services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter, NostrLoginStartupFilter>();
        services.AddUIExtension("user-nav", "/Views/NostrLogin/UserNav.cshtml");
        services.AddUIExtension("server-nav", "/Views/NostrLogin/ServerNav.cshtml");
    }
}
