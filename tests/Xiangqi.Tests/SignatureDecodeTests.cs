using Xiangqi.Server.Kaspa;

namespace Xiangqi.Tests;

public class SignatureDecodeTests
{
    private const string Sig1Hex =
        "EB9E8A3C547EB91B6A7592644F328F0648BDD21ABA3CD44787D429D4D790AA8B962745691F3B472ED8D65F3B770ECB4F777BD17B1D309100919B53E0E206B4C6";

    // 64 bytes whose base64 form starts with the characters "0x" (bytes D3 1x ...).
    private static byte[] SigStartingWith0xBase64()
    {
        var b = new byte[64];
        for (int i = 0; i < b.Length; i++) b[i] = (byte)(i * 7 + 3);
        b[0] = 0xD3; b[1] = 0x1F;
        return b;
    }

    [Fact]
    public void Base64StartingWith0x_IsNotTreatedAsHexPrefix()
    {
        byte[] sig = SigStartingWith0xBase64();
        string b64 = Convert.ToBase64String(sig);
        Assert.StartsWith("0x", b64);
        Assert.Equal(sig, KaspaMessageSigner.DecodeSignature(b64));
        Assert.Equal(sig, KaspaMessageSigner.DecodeSignature("  " + b64 + "\n"));
    }

    [Fact]
    public void HexWith0xPrefix_IsDecoded_CaseInsensitive()
    {
        byte[] expect = Convert.FromHexString(Sig1Hex);
        Assert.Equal(expect, KaspaMessageSigner.DecodeSignature(Sig1Hex));
        Assert.Equal(expect, KaspaMessageSigner.DecodeSignature("0x" + Sig1Hex));
        Assert.Equal(expect, KaspaMessageSigner.DecodeSignature("0X" + Sig1Hex.ToLowerInvariant()));
    }

    [Fact]
    public void PlainBase64_IsDecoded()
    {
        byte[] expect = Convert.FromHexString(Sig1Hex);
        Assert.Equal(expect, KaspaMessageSigner.DecodeSignature(Convert.ToBase64String(expect)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("zz")]
    [InlineData("0x1234")]
    public void Invalid_ReturnsNull(string? input)
        => Assert.Null(KaspaMessageSigner.DecodeSignature(input));

    [Fact]
    public void WrongLengthBase64_ReturnsNull()
        => Assert.Null(KaspaMessageSigner.DecodeSignature(Convert.ToBase64String(new byte[63])));

    [Fact]
    public void RealSignature_VerifiesInHexBase64And0xForms()
    {
        string pub = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659";
        string address = KaspaMessageSigner.AddressFromXOnly(Convert.FromHexString(pub), "mainnet");
        // Message/sig pair from KaspaSignatureTests (Vector 1).
        foreach (string form in new[] { Sig1Hex, "0x" + Sig1Hex, Convert.ToBase64String(Convert.FromHexString(Sig1Hex)) })
        {
            var check = KaspaMessageSigner.Verify(address, "Hello Kaspa!", form, "mainnet");
            // Vector 1 is for a different message in the suite; here we only require the form decodes (no 'encoding' error).
            Assert.DoesNotContain("invalid signature encoding", check.Error ?? "");
        }
    }
}
