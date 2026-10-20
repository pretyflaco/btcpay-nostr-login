using System.Text.RegularExpressions;

namespace BTCPayServer.Plugins.NostrLogin.Tests;

/// <summary>
/// Markup guards for the plugin's Razor views.
/// </summary>
public class ViewMarkupTests
{
    private static string ViewsDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src", "BTCPayServer.Plugins.NostrLogin", "Views")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src", "BTCPayServer.Plugins.NostrLogin", "Views");
    }

    public static TheoryData<string> Views()
    {
        var data = new TheoryData<string>();
        foreach (var f in Directory.GetFiles(ViewsDir(), "*.cshtml", SearchOption.AllDirectories))
            data.Add(Path.GetFileName(f));
        return data;
    }

    // An element start tag carrying the hidden attribute.
    private static readonly Regex HiddenTag = new(@"<[a-zA-Z][^<>]*\shidden(\s|>|/)[^<>]*>?", RegexOptions.Compiled);
    // Bootstrap display utilities are display:...!important and override [hidden].
    private static readonly Regex DisplayUtility = new(@"class=""[^""]*\bd-(none|inline|inline-block|block|grid|inline-grid|table|table-row|table-cell|flex|inline-flex)\b", RegexOptions.Compiled);

    /// <summary>
    /// `hidden` on an element with a Bootstrap d-* display class does nothing (the class is
    /// !important): it once left a second spinner and a duplicate "signer app" link visible.
    /// Put `hidden` on a plain wrapper instead.
    /// </summary>
    [Theory]
    [MemberData(nameof(Views))]
    public void HiddenIsNeverCombinedWithBootstrapDisplayClass(string view)
    {
        var markup = File.ReadAllText(Directory.GetFiles(ViewsDir(), view, SearchOption.AllDirectories).Single());
        var offenders = HiddenTag.Matches(markup).Select(m => m.Value).Where(t => DisplayUtility.IsMatch(t)).ToList();
        Assert.Empty(offenders);
    }

    private static readonly Regex ScriptLookup = new(@"getElementById\(""([^""]+)""\)", RegexOptions.Compiled);

    internal static List<string> ScriptToggledDisplayClassElements(IEnumerable<string> markups)
    {
        var all = markups.ToList();
        // Ids the views' scripts look up (the partial's script also reaches into the pages).
        var ids = all.SelectMany(m => ScriptLookup.Matches(m).Select(x => x.Groups[1].Value)).ToHashSet();
        return all.SelectMany(m => Regex.Matches(m, @"<[a-zA-Z][^<>]*\sid=""([^""]+)""[^<>]*>").Select(x => (Tag: x.Value, Id: x.Groups[1].Value)))
            .Where(t => ids.Contains(t.Id) && DisplayUtility.IsMatch(t.Tag))
            .Select(t => t.Tag)
            .ToList();
    }

    /// <summary>
    /// Scripts show/hide elements by id (hidden / style.display), and neither beats a Bootstrap
    /// d-* class (!important): such elements must not carry one; wrap the d-flex content instead.
    /// </summary>
    [Fact]
    public void ScriptToggledElements_HaveNoBootstrapDisplayClass()
    {
        var markups = Directory.GetFiles(ViewsDir(), "*.cshtml", SearchOption.AllDirectories).Select(File.ReadAllText);
        Assert.Empty(ScriptToggledDisplayClassElements(markups));
    }

    [Fact]
    public void Guard_DetectsTheOriginalBug()
    {
        const string bad = "<div class=\"d-flex align-items-center my-4\" id=\"NostrOrDivider\" hidden>";
        Assert.Contains(HiddenTag.Matches(bad), m => DisplayUtility.IsMatch(m.Value));
        Assert.DoesNotContain(HiddenTag.Matches("<div id=\"NostrOrDivider\" hidden>"), m => DisplayUtility.IsMatch(m.Value));
    }
}
