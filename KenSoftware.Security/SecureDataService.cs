using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KenSoftware.Security;

public class SecureDataService : ISecureDataService
{
    private readonly IDataProtector _protector;
    private readonly TimeSpan _defaultTtl;

    public SecureDataService(
       IDataProtectionProvider provider,
       IOptions<SecurityOptions> options)
    {
        _protector = provider.CreateProtector("KenSoftware.Security.v1");
        _defaultTtl = options.Value.DefaultTtl;
    }

    public string Encrypt(string plaintext, TimeSpan? ttl = null)
    {
        var effectiveTtl = ttl ?? _defaultTtl;

        var payload = new Payload
        {
            Data = plaintext,
            Expiry = DateTime.UtcNow.Add(effectiveTtl)
        };

        var json = JsonSerializer.Serialize(payload);
        return _protector.Protect(json);
    }

    public string Decrypt(string protectedData)
    {
        if (string.IsNullOrEmpty(protectedData))
            return string.Empty;

        var json = _protector.Unprotect(protectedData);

        var payload = JsonSerializer.Deserialize<Payload>(json);

        if (payload == null || DateTime.UtcNow > payload.Expiry)
            throw new CryptographicException("Data expired");

        return payload.Data;
    }

    public T Decrypt<T>(string protectedData)
    {
        var result = Decrypt(protectedData);

        return string.IsNullOrEmpty(result)
            ? default!
            : JsonSerializer.Deserialize<T>(result)!;
    }

    private class Payload
    {
        public string Data { get; set; } = string.Empty;
        public DateTime Expiry { get; set; }
    }
}
