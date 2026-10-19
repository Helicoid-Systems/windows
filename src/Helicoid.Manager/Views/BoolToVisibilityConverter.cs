using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Helicoid.Manager.Views;

/// <summary>Bool to Visibility for tile templates. No inventing live state.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        value is Visibility.Visible;
}
