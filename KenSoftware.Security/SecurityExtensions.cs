namespace KenSoftware.Security;

public static class SecurityExtensions
{
    public static string Encrypt(this string obj)
    {
        if (obj == null) return string.Empty;

        return SecurityProvider.SecureData.Encrypt(obj);
    }

    public static string Encrypt(this string obj, TimeSpan ttl)
    {
        if (obj == null) return string.Empty;

        return SecurityProvider.SecureData.Encrypt(obj, ttl);
    }

    public static string Decrypt(this string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        return SecurityProvider.SecureData.Decrypt(text);
    }

    public static T Decrypt<T>(this string text) where T : struct
    {
        if (string.IsNullOrEmpty(text)) return default;

        return SecurityProvider.SecureData.Decrypt<T>(text);
    }
}





