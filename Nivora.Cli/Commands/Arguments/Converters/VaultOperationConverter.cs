using System.ComponentModel;
using Nivora.Core.Enums;

namespace Nivora.Cli.Commands.Arguments.Converters;

public class VaultOperationConverter : TypeConverter
{
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType)
    {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }

    public override object ConvertFrom(ITypeDescriptorContext? context, System.Globalization.CultureInfo? culture, object value)
    {
        if (value is not string strValue) return base.ConvertFrom(context, culture, value);
        if (Enum.TryParse<VaultOperation>(strValue, true, out var operation))
        {
            return operation;
        }
        return base.ConvertFrom(context, culture, value);
    }
}