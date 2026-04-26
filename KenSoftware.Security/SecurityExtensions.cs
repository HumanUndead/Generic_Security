using Qimmah.Extensions;
using System.Security.Cryptography;
using System.Text;

namespace Qimmah.Security;

public static class SecurityExtensions
{
    private static readonly string password = "RjHIld5PuOs5G62Z";

    public static string Encrypt(this object obj)
    {
        if (obj == null)
        {
            return string.Empty;
        }

        return ConvertStringToBase64(Cryptography.Encrypt(Aes.Create(), obj.ToString(), password, TimeSpan.FromSeconds(10)), Encoding.Unicode);
    }

    public static string Decrypt(this string text)
    {
        return Cryptography.Decrypt(Aes.Create(), ConvertBase64ToString(text, Encoding.Unicode), password);
    }


    public static T Decrypt<T>(this string text)
    {
        if (text.IsNotNullOrEmpty())
        {
            return Cryptography.Decrypt(Aes.Create(), ConvertBase64ToString(text, Encoding.Unicode), password).ToAnyType<T>();
        }
        return text.ToAnyType<T>();
    }


    public static bool Decrypt<T>(this string text, T ValueToCheck, out T value)
    {
        if (text.IsNotNullOrEmpty())
        {
            value = Cryptography.Decrypt(Aes.Create(), ConvertBase64ToString(text, Encoding.Unicode), password).ToAnyType<T>();
            return !value.Equals(ValueToCheck);
        }
        value = text.ToAnyType<T>();
        return false;
    }


    public static bool Decrypt<T>(this string text, out T value)
    {
        if (text.IsNotNullOrEmpty())
        {
            value = Cryptography.Decrypt(Aes.Create(), ConvertBase64ToString(text, Encoding.Unicode), password).ToAnyType<T>();
            return !value.Equals(default(T));
        }
        value = text.ToAnyType<T>();
        return false;
    }

    public static string ConvertStringToBase64(string input, Encoding encoding)
    {
        byte[] bytes = encoding.GetBytes(input);
        return Convert.ToBase64String(bytes);
    }

    public static string ConvertBase64ToString(string base64Input, Encoding encoding)
    {
        byte[] bytes = Convert.FromBase64String(base64Input);
        return encoding.GetString(bytes);
    }

  
    private static string GetImageExtensionFromMIMEType(string mimeType)
    {
        switch (mimeType.ToLower())
        {
            case "image/png":
                return "png";

            case "image/jpeg":
            case "image/jpg":
            case "image/pjpeg": // Alternative for JPEG
                return "jpeg";

            case "image/gif":
                return "gif";

            case "image/bmp":
                return "bmp";

            case "image/webp":
                return "webp";

            case "image/tiff":
            case "image/tif": // Alternative for TIFF
                return "tiff";

            case "image/x-icon":
            case "image/vnd.microsoft.icon": // Alternate MIME for ICO
                return "ico";

            case "image/svg+xml":
                return "svg";

            case "image/avif":
                return "avif";

            case "image/heic":
                return "heic";

            default:
                return string.Empty;
        }

    }

}
