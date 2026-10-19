using Helicoid.Domain.Model;
using Helicoid.Manager.ViewModels;

namespace Helicoid.Manager.Views;

/// Native viewers outlive inventory pages and keep receiving session invalidations.
public sealed class ViewerWindowCoordinator
{
    private readonly MainViewModel _model;
    private readonly Dictionary<int, ViewScreenWindow> _windows = new();

    public ViewerWindowCoordinator(MainViewModel model)
    {
        _model = model;
        _model.Viewers.Changed += OnViewersChanged;
    }

    public void Open(ComputerId computerId)
    {
        var tile = _model.AllAuthorizedTiles.FirstOrDefault(t => t.Id == computerId);
        if (tile is null) return;
        var token = _model.OpenViewScreen(computerId);
        if (_windows.TryGetValue(token.Handle, out var existing))
        {
            existing.Activate();
            return;
        }
        var window = new ViewScreenWindow(
            tile.Name, _model.ScreenUnavailableTitle, "The remote-view engine is not available in this build.",
            token.SessionContext, handle =>
            {
                _windows.Remove(handle);
                _model.CloseViewScreen(handle);
            });
        _windows.Add(token.Handle, window);
        window.ShowViewer(token.Handle);
    }

    private void OnViewersChanged(object? sender, EventArgs e)
    {
        foreach (var (handle, window) in _windows.ToArray())
        {
            if (!_model.Viewers.IsLive(handle)) window.Close();
        }
    }
}
