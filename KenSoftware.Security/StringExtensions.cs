using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Qimmah.Extensions;
public static class StringExtensions
{
    public static bool IsNotNullOrEmpty([NotNullWhen(true)] this string value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }
    public static bool IsNotNullOrEmpty([NotNullWhen(true)] this string value, out string checkedValue)
    {
        // Initialize the out parameter
        checkedValue = value;

        // Check if the value is not null or whitespace
        bool isNotNullOrEmpty = !string.IsNullOrWhiteSpace(value);

        // If the value is null or whitespace, set checkedValue to null
        if (!isNotNullOrEmpty)
        {
            checkedValue = null;
        }

        return isNotNullOrEmpty;
    }
    public static string IsNotNullOrEmptyString([NotNullWhen(true)] this string value)
    {
        return !string.IsNullOrWhiteSpace(value) ? value : "";
    }

    public static string GetValueFromMultipleStrings(this string value1, params string[] values)
    {
        if (value1.IsNotNullOrEmpty())
        {
            return value1;
        }
        else if (values.IsNotNullOrEmpty())
        {
            return Array.Find(values, x => x.IsNotNullOrEmpty());
        }
        return string.Empty;
    }

    public static int GetNIndex(this string input, char chr, int N)
    {
        if (N <= 0)
        {
            return -1;
        }
        int slashCount = 0;
        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == chr)
            {
                slashCount++;
                if (slashCount == N)
                {
                    return i;
                }
            }
        }
        return input.GetNIndex('/', N - 1);
    }

    public static string Base64Encode(this string plainText)
    {
        var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        return Convert.ToBase64String(plainTextBytes);
    }
    public static string Base64Decode(this string base64EncodedData)
    {
        var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
        return Encoding.UTF8.GetString(base64EncodedBytes);
    }
    public static string ConvertByteArrayToBase64(this byte[] byteArray, string MimeTypes)
    {
        string base64Data = Convert.ToBase64String(byteArray);
        return $"data:{MimeTypes};base64,{base64Data}";
    }

    public static string ObjectToQueryParams(this object obj)
    {
        if (obj.IsNotNullOrEmpty())
        {
            var properties = obj.GetType().GetProperties();

            StringBuilder queryString = new StringBuilder();

            foreach (var property in properties)
            {
                string propertyName = property.Name;
                object propertyValue = property.GetValue(obj);

                if (propertyValue != null)
                {
                    string encodedName = Uri.EscapeDataString(propertyName);
                    string encodedValue = Uri.EscapeDataString(propertyValue.ToString());

                    if (queryString.Length == 0)
                    {
                        queryString.Append($"?{encodedName}={encodedValue}");
                    }
                    else
                    {
                        queryString.Append($"&{encodedName}={encodedValue}");
                    }
                }
            }

            return queryString.ToString();
        }

        return "";
    }


    public static string GetUrlPrepare(string URL, object ojb)
    {
        string newURl = URL;
        return newURl + ojb.ObjectToQueryParams();
    }

    public static string ToCamelCase(this string str)
    {
        if (string.IsNullOrEmpty(str))
            return str;

        if (str.Length == 1)
            return str.ToLower();

        return char.ToLowerInvariant(str[0]) + str.Substring(1);
    }
}

