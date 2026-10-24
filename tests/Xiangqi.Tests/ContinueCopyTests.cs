using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xiangqi.Server;

namespace Xiangqi.Tests;

/// <summary>Copy requirements: pre-payment rules, unactivated-payment contact hint, and a 402 price that comes from config.</summary>
public class ContinueCopyTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public ContinueCopyTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private static string WwwRoot(string file)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "src", "Xiangqi.Server", "wwwroot", file);
            if (File.Exists(candidate))
                return File.ReadAllText(candidate);
            dir = dir.Parent;
        }

        throw new FileNotFoundException(file);
    }

    [Theory]
    [InlineData("1", "100000000", "1 KAS")]
    [InlineData("2", "250000000", "2.5 KAS")]
    public async Task Move402_UsesConfiguredPrice(string _, string sompi, string expected)
    {
        var c = ContinueHarness.Configured(_factory, null, 1100, null, ("Payment:PriceSompi", sompi));
        var s = await ContinueHarness.Create(c);
        var (status, body) = await ContinueHarness.Move(c, s, "马二进三");
        Assert.Equal(HttpStatusCode.PaymentRequired, status);
        string error = body.GetProperty("error").GetString()!;
        Assert.Contains(ContinueService.FeeLabel, error);
        Assert.Contains(expected, error);
        Assert.Contains("payment required", error);
    }

    [Fact]
    public void Index_HasRulesBeforePayment_Bilingual_WithDynamicConfirmations()
    {
        string html = WwwRoot("index.html");
        Assert.Contains("id=\"contRules\"", html);
        Assert.Contains("仅用签名地址付款、单笔支付、需", html);
        Assert.Contains("个确认", html);
        Assert.Contains("only from the signed address", html);
        Assert.Contains("single transaction", html);
        Assert.Contains("续弈服务费", html);
        Assert.Contains("id=\"contMinConf\"", html);
        // the rules sit in the static continue description, before the (hidden) payment box
        Assert.True(html.IndexOf("id=\"contRules\"", StringComparison.Ordinal) < html.IndexOf("id=\"payBox\"", StringComparison.Ordinal));
        // the number of confirmations is not hardcoded in the markup
        Assert.DoesNotContain("需 10 个确认", html);
        Assert.DoesNotContain("需10个确认", html);
    }

    [Fact]
    public void Index_PaymentArea_HasUnactivatedHelp_WithPlaceholderContact()
    {
        string html = WwwRoot("index.html");
        int box = html.IndexOf("id=\"payBox\"", StringComparison.Ordinal);
        int help = html.IndexOf("id=\"payHelp\"", StringComparison.Ordinal);
        Assert.True(help > box);
        Assert.Contains("已付款但未激活，请联系站长并提供 txid", html);
        Assert.Contains("chess@kastop.com", html);
        Assert.Contains("Paid but not activated", html);
        Assert.Contains("chess@kastop.com", html);
    }

    [Fact]
    public void ContinueJs_FillsConfirmationsAndPriceFromConfig_NoHardcodedKas()
    {
        string js = WwwRoot("continue.js");
        Assert.Contains("cfg.minConfirmations", js);
        Assert.Contains("contMinConf", js);
        Assert.DoesNotContain("1 KAS", js);
        Assert.DoesNotContain("1 KAS", WwwRoot("index.html"));
    }
}
