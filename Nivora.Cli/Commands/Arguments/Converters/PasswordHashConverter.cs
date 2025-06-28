using System.ComponentModel;
using System.Globalization;
using Nivora.Core.Models;

namespace Nivora.Cli.Commands.Arguments.Converters;

public class PasswordHashConverter : TypeConverter
{
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType)
    {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }

    public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value)
    {
        if (value is string strValue)
        {
            return PasswordHash.FromPlainText(strValue);
        }
        return PasswordHash.Empty;
    }
}