namespace Yonderfix.Web.Services;

public class SettingsService
{
    private int _pageSize = 20;
    private readonly object _lock = new();

    public int PageSize
    {
        get { lock (_lock) { return _pageSize; } }
    }

    public AppSettings GetSettings()
    {
        lock (_lock)
        {
            return new AppSettings { PageSize = _pageSize };
        }
    }

    public void UpdatePageSize(int pageSize)
    {
        if (pageSize < 5) pageSize = 5;
        if (pageSize > 100) pageSize = 100;

        lock (_lock)
        {
            _pageSize = pageSize;
        }
    }
}

public class AppSettings
{
    public int PageSize { get; set; } = 20;
}
