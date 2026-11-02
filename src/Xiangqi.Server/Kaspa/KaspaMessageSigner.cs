using NKaspa;
using NKaspa.Crypto;

namespace Xiangqi.Server.Kaspa;

/// <summary>
/// Kaspa personal-message signing as implemented by rusty-kaspa
/// (wallet/core/src/message.rs) and used by KasWare's Schnorr signMessage:
/// digest = BLAKE2b-256(key = "PersonalMessageSigningHash", utf8(message)),
/// signature = BIP340 Schnorr over that digest with the address's x-only key.
/// Crypto, address parsing and hashing are delegated to the NKaspa package (PersonalMessage,
/// KaspaAddress); this class keeps the server-facing façade and bilingual error strings.
/// </summary>
public static class KaspaMessageSigner
{
    public static byte[] PersonalMessageHash(string message) => PersonalMessage.Hash(message);

    public static string AddressPrefix(string network) =>
        network.Trim().ToLowerInvariant() switch
        {
            "mainnet" or "" => "kaspa",
            "testnet" or "testnet-10" or "testnet-11" => "kaspatest",
            "devnet" => "kaspadev",
            "simnet" => "kaspasim",
            _ => throw new ArgumentException($"Unknown Kaspa network '{network}'."),
        };

    /// <summary>Decodes a 64-byte Schnorr signature from hex (128 chars) or base64.</summary>
    public static byte[]? DecodeSignature(string? signature)
    {
        if (string.IsNullOrWhiteSpace(signature))
            return null;
        string s = signature.Trim();
        // Hex: optional 0x prefix, exactly 128 hex chars. The prefix is only removed for a hex
        // reading; a base64 string may legitimately begin with "0x" and must stay intact.
        string hex = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
        if (hex.Length == 128)
        {
            try { return Convert.FromHexString(hex); } catch (FormatException) { }
        }
        try
        {
            byte[] raw = Convert.FromBase64String(s);
            return raw.Length == 64 ? raw : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public static bool VerifyDigest(ReadOnlySpan<byte> xOnly, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> sig)
    {
        if (xOnly.Length != 32 || digest.Length != 32 || sig.Length != 64)
            return false;
        try
        {
            return new PubKey(xOnly).Verify(new SchnorrSignature(sig), digest);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies that <paramref name="signature"/> signs <paramref name="message"/> with the key
    /// encoded in a Schnorr P2PK <paramref name="address"/> on the expected network.
    /// </summary>
    public static SignatureCheck Verify(string? address, string message, string? signature, string network)
    {
        string? trimmed = address?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(trimmed) || !KaspaAddress.TryParse(trimmed, out var addr) || addr is null)
            return SignatureCheck.Fail("地址格式无效 / invalid Kaspa address");
        if (!string.Equals(addr.Network.AddressPrefix, AddressPrefix(network), StringComparison.Ordinal))
            return SignatureCheck.Fail($"地址网络不匹配，需要 {AddressPrefix(network)}: 前缀 / wrong network");
        if (addr.Version != KaspaAddressVersion.PubKey)
            return SignatureCheck.Fail("仅支持 Schnorr 地址（kaspa:q…）签名验证 / only Schnorr P2PK addresses are supported");
        byte[]? sig = DecodeSignature(signature);
        if (sig is null)
            return SignatureCheck.Fail("签名格式无效（需 64 字节 Schnorr 签名，hex 或 base64） / invalid signature encoding");
        bool ok;
        try { ok = PersonalMessage.VerifyMessage(addr, message, new SchnorrSignature(sig)); }
        catch (ArgumentException) { ok = false; }
        return ok ? SignatureCheck.Ok() : SignatureCheck.Fail("签名验证失败 / signature does not match address");
    }

    /// <summary>
    /// Signs like rusty-kaspa sign_message (used by tests and tooling). Without
    /// <paramref name="auxRand32"/> a zero aux is used so output stays deterministic.
    /// </summary>
    public static byte[] Sign(string message, ReadOnlySpan<byte> privateKey32, byte[]? auxRand32 = null)
    {
        using var key = CreateKey(privateKey32);
        byte[] aux = auxRand32 is { Length: 32 } ? auxRand32 : new byte[32];
        return PersonalMessage.SignMessage(key, message, aux).ToBytes();
    }

    public static byte[] XOnlyPublicKey(ReadOnlySpan<byte> privateKey32)
    {
        using var key = CreateKey(privateKey32);
        return key.PubKey.ToBytes();
    }

    public static string AddressFromXOnly(ReadOnlySpan<byte> xOnly, string network) =>
        new PubKey(xOnly).GetAddress(NetworkFor(network)).ToString();

    private static Network NetworkFor(string network)
    {
        string prefix = AddressPrefix(network);
        return Network.TryFromAddressPrefix(prefix, out var n) && n is not null
            ? n
            : throw new ArgumentException($"Unknown Kaspa network '{network}'.");
    }

    private static Key CreateKey(ReadOnlySpan<byte> privateKey32)
    {
        try { return new Key(privateKey32); }
        catch (ArgumentException) { throw new ArgumentException("Invalid private key."); }
    }
}

public sealed record SignatureCheck(bool Valid, string? Error)
{
    public static SignatureCheck Ok() => new(true, null);
    public static SignatureCheck Fail(string error) => new(false, error);
}
