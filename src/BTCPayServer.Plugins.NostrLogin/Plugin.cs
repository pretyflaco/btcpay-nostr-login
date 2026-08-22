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
        // Durable NIP-98 replay guard (audit finding 5): consumed event ids survive restarts.
        services.AddSingleton<Nip98ReplayStore>();
        services.AddHostedService<Nip98ReplayStore>(sp => sp.GetRequiredService<Nip98ReplayStore>());
        services.AddSingleton<NostrProfilePictureService>();
        services.AddHttpClient();
        // SSRF-guarded client for attacker-chosen avatar URLs (audit finding 4): every
        // connection resolves DNS itself and refuses private/link-local targets.
        services.AddHttpClient(NostrProfilePictureService.GuardedHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => NostrProfilePictureService.CreateGuardedHandler());
        services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter, NostrLoginStartupFilter>();
        services.AddUIExtension("user-nav", "/Views/NostrLogin/UserNav.cshtml");
        services.AddUIExtension("server-nav", "/Views/NostrLogin/ServerNav.cshtml");
    }
}
