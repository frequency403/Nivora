using System.ComponentModel;
using System.Globalization;

namespace Nivora.Cli.Commands.Arguments.Converters;

public class ByteArrayConverter : TypeConverter
{
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType)
    {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }

    public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value)
    {
        if (value is string strValue)
        {
            return System.Text.Encoding.UTF8.GetBytes(strValue);
        }
        return Array.Empty<byte>();
    }
}